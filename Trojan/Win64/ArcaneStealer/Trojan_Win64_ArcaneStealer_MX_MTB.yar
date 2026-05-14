
rule Trojan_Win64_ArcaneStealer_MX_MTB{
	meta:
		description = "Trojan:Win64/ArcaneStealer.MX!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 72 63 61 6e 65 70 61 6e 65 6c 2e 63 63 } //1 arcanepanel.cc
		$a_01_1 = {41 00 72 00 63 00 61 00 6e 00 65 00 55 00 70 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 31 00 2e 00 30 00 } //1 ArcaneUploader/1.0
		$a_01_2 = {43 6f 6f 6b 69 65 73 3a } //1 Cookies:
		$a_01_3 = {78 00 57 00 69 00 6e 00 33 00 32 00 5f 00 44 00 69 00 73 00 6b 00 44 00 72 00 69 00 76 00 65 00 } //1 xWin32_DiskDrive
		$a_01_4 = {42 72 75 74 65 2e 74 78 74 } //1 Brute.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}