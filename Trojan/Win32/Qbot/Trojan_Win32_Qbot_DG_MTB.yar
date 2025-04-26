
rule Trojan_Win32_Qbot_DG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6b 39 70 66 6c 2e 64 6c 6c } //1 k9pfl.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {4d 69 66 44 74 7a 61 4d 68 67 47 } //1 MifDtzaMhgG
		$a_81_3 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //1 ZHxbETopuOI
		$a_81_4 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //1 jKuEkhbMkMhYKG
		$a_81_5 = {67 55 6d 61 6d 58 50 } //1 gUmamXP
		$a_81_6 = {45 71 75 61 6c 52 67 6e } //1 EqualRgn
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}