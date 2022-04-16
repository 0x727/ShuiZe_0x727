import datetime
import os
import configparser
import json

cf = configparser.ConfigParser()
cf.read("./iniFile/config.ini")
secs = cf.sections()
nuclei_config = cf.get('nuclei config', 'nuclei_config')

def getCurrent_time():
    current_time = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')).replace(' ', '-').replace(':', '-')
    return current_time

def run_nuclei(alive_Web):
    nucleiVul_list = []

    nucleiFolder = "./Plugins/Vul/Nuclei"

    # 保存nuclei结果的文件夹
    nucleiResult_folder = "{}/nucleiResult/{}".format(nucleiFolder, getCurrent_time())
    os.makedirs(nucleiResult_folder)

    # 将alive_Web的url内容保存到文件里
    urlFilePath = nucleiResult_folder + "/url.txt"
    with open(urlFilePath, 'at', encoding='utf-8') as f:
        for url in alive_Web:
            f.writelines("{}\n".format(url))

    # 保存nuclei结果的文件路径
    nucleiResultPath = nucleiResult_folder + "/nucleiResult.txt"

    # 赋予执行权限
    os.system('chmod 777 {}/nuclei'.format(nucleiFolder))

    # 更新nuclei模板
    nucleiUpdateCMD = '{}/nuclei -ud {}/nuclei-templates/'.format(nucleiFolder, nucleiFolder)
    print("[更新nuclei-template] : {}".format(nucleiUpdateCMD))
    os.system(nucleiUpdateCMD)

    # 运行nuclei检测漏洞
    nucleiCMD = '{}/nuclei -l {} {} -json -o {}'.format(nucleiFolder, urlFilePath, nuclei_config, nucleiResultPath)
    print("[nucleiCMD] : {}".format(nucleiCMD))
    os.system(nucleiCMD)

    # nucleiResultPath = "Plugins/Vul/Nuclei/nucleiResult/2022-04-16-18-34-09/nucleiResult.txt"
    # 读取nuclei结果
    with open(nucleiResultPath, 'rt', encoding='utf-8') as f:
        for eachLine in f.readlines():
            eachLine = eachLine.strip()
            nucleiResult = json.loads(eachLine)
            url, vulName, templateId, severity, currentTime = nucleiResult["host"], nucleiResult["info"]["name"], \
                                                              nucleiResult["template-id"], nucleiResult["info"][
                                                                  "severity"], nucleiResult["timestamp"]
            print(url, vulName, templateId, severity, currentTime)
            nucleiVul_list.append([vulName, url, templateId])

    return nucleiVul_list


if __name__ == '__main__':
    alive_Web = ['']
    run_nuclei(alive_Web)