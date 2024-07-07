
rule Backdoor_BAT_WebShell_GMF_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {6d 00 65 00 69 00 7a 00 68 00 69 00 2e 00 69 00 6e } //m  1
		$a_80_1 = {46 61 4b 65 20 53 68 65 6c 6c 20 42 79 20 46 34 6b 33 72 } //FaKe Shell By F4k3r  1
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 75 73 65 72 } //cmd.exe /c net user  1
		$a_01_3 = {63 79 52 43 62 4c 76 } //1 cyRCbLv
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}