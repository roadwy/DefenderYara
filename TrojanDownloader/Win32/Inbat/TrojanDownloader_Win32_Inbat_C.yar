
rule TrojanDownloader_Win32_Inbat_C{
	meta:
		description = "TrojanDownloader:Win32/Inbat.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 4d 59 46 49 4c 45 53 25 5c 55 70 64 2e 65 78 65 } //2 %MYFILES%\Upd.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 } //2 http://%computername%
		$a_01_2 = {2e 66 65 6e 67 79 6f 75 2e 6e 65 74 2f } //1 .fengyou.net/
		$a_01_3 = {2e 6e 61 69 67 65 2e 63 6f 6d 2e 63 6e 2f } //1 .naige.com.cn/
		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 75 6e 6c 65 69 31 30 30 2e 63 6f 6d } //1 http://www.xunlei100.com
		$a_01_5 = {00 55 50 64 2e 65 78 65 00 } //1
		$a_01_6 = {70 69 70 69 5f 64 61 65 5f } //1 pipi_dae_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}