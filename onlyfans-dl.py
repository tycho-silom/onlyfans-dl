#!/usr/bin/python
#
# OnlyFans Profile Downloader/Archiver
# KORNHOLIO 2020
#
# See README for help/info.
#
# This program is Free Software, licensed under the
# terms of GPLv3. See LICENSE.txt for details.
import copy
import re
import os
import sys
import json
import shutil
import requests
import time
import datetime as dt
from urllib.parse import urlencode, urlparse
import hashlib
from requests import sessions

# Initialize variables (Purely cosmetic to stop linters from throwing errors)
POST_LIMIT = "100"
URL = "https://onlyfans.com"
API_URL = "/api2/v2"
APP_TOKEN = "33d57ade8c02dbc5a333db99ff9ae26a"

DEBUG = False


# move dynamic data out of the __main__
# config.json template added to git and gitignore.
def parse_config(filename):
    with open(filename, 'r') as f:
        return json.load(f)


# helper function to make sure a dir is present
def assure_dir(path):
    if not os.path.isdir(path):
        os.mkdir(path)


def build_url(endpoint, getparams):
    link = URL + API_URL + endpoint
    if getparams:
        link += f'?{urlencode(getparams)}'
    return link


def get_id_from_path(path):
    last_index = path.rfind("/")
    second_last_index = path.rfind("/", 0, last_index - 1)
    return path[second_last_index + 1:last_index]


def calc_process_time(starttime, arraykey, arraylength):
    timeelapsed = time.time() - starttime
    timeest = (timeelapsed / arraykey) * (arraylength)
    finishtime = starttime + timeest
    finishtime = dt.datetime.fromtimestamp(finishtime).strftime("%H:%M:%S")  # in time
    lefttime = dt.timedelta(seconds=(int(timeest - timeelapsed)))  # get a nicer looking timestamp this way
    timeelapseddelta = dt.timedelta(seconds=(int(timeelapsed)))  # same here
    return (timeelapseddelta, lefttime, finishtime)


class ProfileDownload:
    def __init__(self, target_username, downloader):
        self.target_username = target_username
        self.downloader = downloader
        self.starttime = None
        self.total_count = 0
        self.new_files = 0

    def download(self):
        profile_info = self.downloader.get_user_info(self.target_username)

        profile_id = str(profile_info["id"])

        print("\nonlyfans-dl is downloading content to profiles/" + self.target_username + "!\n")

        if os.path.isdir("profiles/" + self.target_username):
            print(f"\nThe profile {self.target_username} exists.")
            print("Existing files will not be re-downloaded.")

        assure_dir("profiles")
        assure_dir(f"profiles/{self.target_username}")
        assure_dir(f"profiles/{self.target_username}/avatar")
        assure_dir(f"profiles/{self.target_username}/header")
        assure_dir(f"profiles/{self.target_username}/photos")
        assure_dir(f"profiles/{self.target_username}/videos")
        assure_dir(f"profiles/{self.target_username}/archived")
        assure_dir(f"profiles/{self.target_username}/archived/photos")
        assure_dir(f"profiles/{self.target_username}/archived/videos")

        # first save profile info
        print("Saving profile info...")

        sinf = {
            "id": profile_info["id"],
            "name": profile_info["name"],
            "username": profile_info["username"],
            "about": profile_info["rawAbout"],
            "joinDate": profile_info["joinDate"],
            "website": profile_info["website"],
            "wishlist": profile_info["wishlist"],
            "location": profile_info["location"],
            "lastSeen": profile_info["lastSeen"]
        }

        with open("profiles/" + self.target_username + "/info.json", 'w') as infojson:
            json.dump(sinf, infojson)

        self.download_public_files(profile_info)

        # get all user posts
        print("Finding photos...", end=' ', flush=True)
        photo_posts = self.downloader.api_request("/users/" + profile_id + "/posts/photos", getdata={"limit": POST_LIMIT})
        if DEBUG:
            print(f'RESPONSE: {photo_posts}')
        print("Found " + str(len(photo_posts)) + " photos.")

        print("Finding videos...", end=' ', flush=True)
        video_posts = self.downloader.api_request("/users/" + profile_id + "/posts/videos", getdata={"limit": POST_LIMIT})
        if DEBUG:
            print(f'RESPONSE: {video_posts}')
        print("Found " + str(len(video_posts)) + " videos.")

        print("Finding archived content...", end=' ', flush=True)
        archived_posts = self.downloader.api_request("/users/" + profile_id + "/posts/archived", getdata={"limit": POST_LIMIT})
        if DEBUG:
            print(f'RESPONSE: {archived_posts}')
        print("Found " + str(len(archived_posts)) + " archived posts.")

        postcount = len(photo_posts) + len(video_posts)
        archived_postcount = len(archived_posts)
        if postcount + archived_postcount == 0:
            print("ERROR: 0 posts found.")
            exit()

        self.total_count = postcount + archived_postcount

        print("Found " + str(self.total_count) + " posts. Downloading media...")

        # get start time for estimation purposes
        self.starttime = time.time()

        cur_count = self.download_posts(1, photo_posts, False)
        cur_count = self.download_posts(cur_count, video_posts, False)
        self.download_posts(cur_count, archived_posts, True)

        print("Downloaded " + str(self.new_files) + " new files.")

        # download public files like avatar and header

    def download_public_files(self, profile_info):
        public_files = ["avatar", "header"]
        for public_file in public_files:
            source = profile_info[public_file]
            if source is None:
                continue
            file_id = get_id_from_path(source)
            file_type = re.findall("\\.\\w+", source)[-1]
            path = "/" + public_file + "/" + file_id + file_type
            if not os.path.isfile("profiles/" + self.target_username + path):
                print("Downloading " + public_file + "...")
                self.download_file(profile_info[public_file], path)
                self.new_files += 1

        # download a media item and save it to the relevant directory

    def download_media(self, media, is_archived):
        id = str(media["id"])
        source = media["source"]["source"]

        if media["type"] not in ["photo", "video"] or not media['canView']:
            return

        # find extension
        ext = re.findall('\\.\\w+\\?', source)
        if len(ext) == 0:
            return
        ext = ext[0][:-1]

        if is_archived:
            path = "/archived/" + media["type"] + "s/" + id + ext
        else:
            path = "/" + media["type"] + "s/" + id + ext
        if not os.path.isfile("profiles/" + self.target_username + path):
            # print(path)
            self.new_files += 1
            self.download_file(source, path)

        # helper to generally download files

    def download_file(self, source, path):
        r = requests.get(source, stream=True)
        with open("profiles/" + self.target_username + path, 'wb') as f:
            r.raw.decode_content = True
            shutil.copyfileobj(r.raw, f)

        # iterate over posts, downloading all media
        # returns the new count of downloaded posts

    def download_posts(self, cur_count, posts, is_archived):
        for k, post in enumerate(posts, start=1):
            if not post["canViewMedia"]:
                continue

            for media in post["media"]:
                if 'source' in media:
                    self.download_media(media, is_archived)

            # adding some nice info in here for download stats
            timestats = calc_process_time(self.starttime, k, self.total_count)
            dwnld_stats = f"{cur_count}/{self.total_count} {round(((cur_count / self.total_count) * 100))}% " + \
                          "Time elapsed: %s, Estimated Time left: %s, Estimated finish time: %s" % timestats
            end = '\n' if cur_count == self.total_count else '\r'
            print(dwnld_stats, end=end)

            cur_count = cur_count + 1

        return cur_count


class OnlyFansDownloader:
    def __init__(self, user_agent, auth_id, auth_hash, sess):
        self.user_agent = user_agent
        self.auth_id = auth_id  # AKA user_id, of logged in user
        self.auth_hash = auth_hash
        self.sess = sess

        self.session = sessions.Session()

        self.common_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate",
            "app-token": APP_TOKEN,
            "User-Agent": self.user_agent,
            "user-id": f"{self.auth_id}",
            "x-bc": ""
        }

        cookies = [
            {'name': 'auth_id', 'value': auth_id},
            {'name': 'sess', 'value': self.sess},
            {'name': 'auth_hash', 'value': self.auth_hash},
            {'name': f'auth_uniq_{auth_id}', 'value': ''},
            {'name': f'auth_uid_{auth_id}', 'value': None},
        ]

        for cookie in cookies:
            self.session.cookies.set(**cookie)

    def create_signed_headers(self, link: str):
        # Users: 300000 | Creators: 301000
        time2 = str(int(round(time.time())))
        # time2 = str(1620203709)
        path = urlparse(link).path
        query = urlparse(link).query
        path = path if not query else f"{path}?{query}"
        static_param = "rhtNVxJh2LD3Jul5MhHcAAnFMysnLlct"
        msg = "\n".join([static_param, time2, path, self.auth_id])
        # print(f'CREATING SIGNED HEADER: msg={msg}')
        message = msg.encode("utf-8")
        hash_object = hashlib.sha1(message)
        sha_1_sign = hash_object.hexdigest()
        sha_1_b = sha_1_sign.encode("ascii")
        checksum = sum(
            [sha_1_b[31], sha_1_b[13], sha_1_b[8], sha_1_b[3], sha_1_b[25], sha_1_b[8], sha_1_b[33], sha_1_b[25], sha_1_b[1], sha_1_b[23],
             sha_1_b[37], sha_1_b[11], sha_1_b[2], sha_1_b[29], sha_1_b[9], sha_1_b[7],
             sha_1_b[29], sha_1_b[30], sha_1_b[18], sha_1_b[25], sha_1_b[18], sha_1_b[21], sha_1_b[10], sha_1_b[37],
             sha_1_b[28], sha_1_b[35], sha_1_b[31], sha_1_b[5],
             sha_1_b[13], sha_1_b[31], sha_1_b[2], sha_1_b[9]]) + 1110

        headers = copy.copy(self.common_headers)
        headers["sign"] = "6:{}:{:x}:609184ae".format(
            sha_1_sign, abs(checksum))
        headers["time"] = time2
        headers['referer'] = link
        return headers

    def validate_config(self):
        if self.sess == "put-sess-cookie-here" or not self.sess:
            return False

        if self.auth_id == "put-auth_id-cookie-here" or not self.auth_id:
            return False

        if self.auth_hash == "put-auth_hash-cookie-here" or not self.auth_hash:
            return False

        return True

    def _request(self, method, link, postdata=None):
        request_header = self.create_signed_headers(link)
        # print(f'LINK={link}, headers={request_header}, cookies={session.cookies} postdata={postdata}')

        return self.session.request(method=method,
                                    url=link,
                                    headers=request_header,
                                    data=postdata)

    def _get_request(self, link):
        return self.session.request(method='GET',
                                    url=link)

    def _post_request(self, link, postdata=None):
        return self.session.request(method='POST',
                                    url=link,
                                    data=postdata)

    # API request convenience function
    # getdata and postdata should both be JSON
    def api_request(self, endpoint, getdata=None, postdata=None):
        getparams = {
            "app-token": APP_TOKEN
        }
        if getdata is not None:
            for i in getdata:
                getparams[i] = getdata[i]

        link = build_url(endpoint, getparams)

        if postdata is not None:
            return self._post_request(link, postdata=postdata)

        if getdata is None:
            return self._get_request(link)

        # Fixed the issue with the maximum limit of 100 posts by creating a kind of "pagination"
        list_base = self._get_request(link).json()
        posts_num = len(list_base)

        if posts_num >= 100:
            before_publish_time = list_base[99]['postedAtPrecise']
            getparams['beforePublishTime'] = before_publish_time
            link = build_url(endpoint, getparams)

            while posts_num == 100:
                # Extract posts
                list_extend = self._get_request(link).json()
                posts_num = len(list_extend)

                if posts_num < 100:
                    break

                # Re-add again the updated beforePublishTime/postedAtPrecise params
                before_publish_time = list_extend[posts_num - 1]['postedAtPrecise']
                getparams['beforePublishTime'] = before_publish_time
                link = build_url(endpoint, getparams)
                # Merge with previous posts
                list_base.extend(list_extend)

        return list_base

    # /users/<profile>
    # get information about <profile>
    # <profile> = "customer" -> info about yourself
    def get_user_info(self, profile):
        info = self.api_request("/users/" + profile).json()
        if DEBUG:
            print(f'RESPONSE: {info}')
        if "error" in info:
            print("\nERROR: " + info["error"]["message"])
            print("\nCheck that the script is updated to the latest or that the the values in config.json are correct.")
            print("\nIf you're still having issues, open an issue: https://github.com/k0rnh0li0/onlyfans-dl/issues/new/choose")
            # bail, we need info for both profiles to be correct
            exit()
        return info

    def login(self):
        self.get_user_info("me")

    def download_profile(self, target_username):
        profile = ProfileDownload(target_username, self)
        profile.download()


def main():
    if len(sys.argv) < 2:
        print("Usage: ./onlyfans-dl <profile>")
        print("See README for instructions.")
        exit()

    # Parses json to variables
    # Ignore linters that claim variables are undefined
    json_config = parse_config("config.json")

    downloader = OnlyFansDownloader(user_agent=json_config.get('User-Agent'),
                                    auth_id=json_config.get('auth_id'),
                                    auth_hash=json_config.get('auth_hash'),
                                    sess=json_config.get('sess'))

    if not downloader.validate_config():
        print("Make sure you configure config.json")
        print("Usage: ./onlyfans-dl <profile>")
        print("See README for instructions.")
        exit()

    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("~ I AM THE GREAT KORNHOLIO ~")
    print("~  ARE U THREATENING ME??  ~")
    print("~                          ~")
    print("~    COOMERS GUNNA COOM    ~")
    print("~    HACKERS GUNNA HACK    ~")
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

    print("Getting user auth info... ")
    downloader.login()

    for target_username in sys.argv[1:]:
        print("Getting target profile info...")
        downloader.download_profile(target_username)


if __name__ == "__main__":
    main()
