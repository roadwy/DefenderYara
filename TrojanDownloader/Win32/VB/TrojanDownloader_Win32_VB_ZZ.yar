
rule TrojanDownloader_Win32_VB_ZZ{
	meta:
		description = "TrojanDownloader:Win32/VB.ZZ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 00 69 00 70 00 70 00 69 00 6e 00 2e 00 63 00 6e 00 2f 00 64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 } //1 vippin.cn/data.txt
		$a_01_1 = {43 6c 73 5f 44 6f 77 6e 4c 6f 61 64 } //1 Cls_DownLoad
		$a_01_2 = {52 00 61 00 76 00 4d 00 6f 00 6e 00 44 00 } //1 RavMonD
		$a_01_3 = {64 00 69 00 61 00 6e 00 78 00 69 00 6e 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 63 00 71 00 2e 00 63 00 6e 00 2f 00 61 00 70 00 69 00 2f 00 74 00 61 00 6f 00 62 00 61 00 6f 00 } //1 dianxin.online.cq.cn/api/taobao
		$a_01_4 = {64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 } //1 del /f del.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}