
rule Trojan_Win32_Webprefix_A{
	meta:
		description = "Trojan:Win32/Webprefix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 76 3d 25 64 2e 25 64 2e 25 64 00 } //1
		$a_00_1 = {53 6f 66 74 77 61 72 65 75 70 64 61 74 65 7c 68 74 74 70 3a 2f 2f } //1 Softwareupdate|http://
		$a_03_2 = {8b 4d 0c bf 04 01 00 00 57 c7 45 ?? 3c 00 00 00 e8 ?? ?? ?? ?? 8b 4d 10 56 89 45 ?? 89 7d ?? e8 ?? ?? ?? ?? 89 45 ?? 8d 45 ?? 50 6a 00 6a 00 89 75 ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 4d 0c 6a ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}