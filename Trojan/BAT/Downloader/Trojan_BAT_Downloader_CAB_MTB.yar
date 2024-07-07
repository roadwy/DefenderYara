
rule Trojan_BAT_Downloader_CAB_MTB{
	meta:
		description = "Trojan:BAT/Downloader.CAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 39 31 2e 32 34 33 2e 34 34 2e 32 32 2f 70 6c 2d 30 30 2d 39 32 2e 6a 70 67 } //1 http://91.243.44.22/pl-00-92.jpg
		$a_01_1 = {24 35 32 39 63 32 30 65 33 2d 30 37 37 35 2d 34 39 32 30 2d 38 63 34 65 2d 37 66 66 61 61 33 39 32 62 63 32 32 } //1 $529c20e3-0775-4920-8c4e-7ffaa392bc22
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {43 6f 6e 73 6f 6c 65 41 70 70 37 2e 65 78 65 } //1 ConsoleApp7.exe
		$a_81_4 = {75 64 32 54 49 4d 66 65 42 41 } //1 ud2TIMfeBA
		$a_81_5 = {65 73 61 65 6c 65 72 2f 20 67 69 66 6e 6f 63 70 69 } //1 esaeler/ gifnocpi
		$a_81_6 = {70 69 6e 67 20 74 77 69 74 74 65 72 2e 63 6f 6d } //1 ping twitter.com
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}