
rule Trojan_Win32_Zloader_SK_MTB{
	meta:
		description = "Trojan:Win32/Zloader.SK!MTB,SIGNATURE_TYPE_PEHSTR,18 00 18 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 65 6d 75 6c 65 2d 6c 6f 61 64 65 72 2d 62 6f 74 33 32 2e 64 6c 6c } //10 antiemule-loader-bot32.dll
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_2 = {45 6e 64 50 61 67 65 } //2 EndPage
		$a_01_3 = {53 74 61 72 74 50 61 67 65 } //2 StartPage
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=24
 
}