
rule Trojan_Win32_BlackMoon_NG_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //2 BlackMoon RunTime Error
		$a_01_1 = {38 40 56 42 53 63 72 69 70 74 2e 52 65 67 45 78 70 } //2 8@VBScript.RegExp
		$a_01_2 = {32 30 32 2e 31 38 39 2e 37 2e 32 33 31 } //1 202.189.7.231
		$a_01_3 = {65 61 69 67 70 75 65 78 2e 64 6c 6c } //1 eaigpuex.dll
		$a_01_4 = {57 69 6e 48 74 74 70 43 72 61 63 6b 55 72 6c } //1 WinHttpCrackUrl
		$a_01_5 = {45 61 69 2e 64 6c 6c } //1 Eai.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}