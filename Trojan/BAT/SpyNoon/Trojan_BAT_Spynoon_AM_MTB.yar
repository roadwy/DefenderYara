
rule Trojan_BAT_Spynoon_AM_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {38 00 35 00 2e 00 32 00 30 00 39 00 2e 00 31 00 37 00 36 00 2e 00 31 00 32 00 36 00 3a 00 33 00 30 00 30 00 30 00 } //2 85.209.176.126:3000
		$a_01_1 = {62 00 61 00 69 00 74 00 65 00 64 00 2e 00 62 00 61 00 74 00 } //1 baited.bat
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}