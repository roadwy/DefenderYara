
rule Trojan_Win32_Danabot_YAA_MTB{
	meta:
		description = "Trojan:Win32/Danabot.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 69 74 37 5c 64 6c 6c 5c 57 6e 64 52 65 73 69 7a 65 72 41 70 70 2e 70 64 62 } //1 git7\dll\WndResizerApp.pdb
		$a_01_1 = {43 49 72 4e 54 7a 42 61 50 6b 70 70 47 4e 66 } //1 CIrNTzBaPkppGNf
		$a_01_2 = {43 5a 6e 49 55 41 41 65 4a } //1 CZnIUAAeJ
		$a_01_3 = {46 78 4a 57 58 64 78 } //1 FxJWXdx
		$a_01_4 = {47 62 6d 67 77 4d 45 7a 4b 70 58 63 } //1 GbmgwMEzKpXc
		$a_01_5 = {48 69 70 58 47 6d 79 67 58 61 70 42 52 59 66 61 } //1 HipXGmygXapBRYfa
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}