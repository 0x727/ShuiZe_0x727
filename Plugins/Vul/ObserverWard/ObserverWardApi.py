import datetime
import os
import json

def getCurrent_time():
    current_time = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')).replace(' ', '-').replace(':', '-')
    return current_time

def run_observerWard(alive_Web):
    observerWardVul_list = []

    observerWardFolder = "./Plugins/Vul/ObserverWard"

    # 保存observerWard结果的文件夹
    observerWardResult_folder = "{}/observerWardResult/{}".format(observerWardFolder, getCurrent_time())
    os.makedirs(observerWardResult_folder)

    # 将alive_Web的url内容保存到文件里
    urlFilePath = observerWardResult_folder + "/url.txt"
    with open(urlFilePath, 'at', encoding='utf-8') as f:
        for url in alive_Web:
            f.writelines("{}\n".format(url))

    # 保存observerWard结果的文件路径
    observerWardResultPath = observerWardResult_folder + "/observerWardResult.json"

    # 赋予执行权限
    os.system('chmod 777 {}/observer_ward'.format(observerWardFolder))

    # 更新observerWard的指纹库
    observerWardUpdateCMD = '{}/observer_ward --update_fingerprint'.format(observerWardFolder)
    print("[更新observerWard指纹库] : {}".format(observerWardUpdateCMD))
    os.system(observerWardUpdateCMD)

    # 运行observerWard检测漏洞
    observerWardCMD = '{}/observer_ward -f {} -j {}'.format(observerWardFolder, urlFilePath, observerWardResultPath)
    print("[observerWardCMD] : {}".format(observerWardCMD))
    os.system(observerWardCMD)

    # observerWardResultPath = "../../../test/1.json"
    # 读取observerWard结果
    with open(observerWardResultPath, 'rt', encoding='utf-8') as f:
        text = f.read()
        if text:
            for each in json.loads(text):
                url, vulName = each["url"], each["name"]
                if vulName:
                    # print(url, vulName)
                    observerWardVul_list.append([str(vulName), url, 'Yes'])

    return observerWardVul_list

if __name__ == '__main__':
    alive_Web = ['']
    run_observerWard(alive_Web)