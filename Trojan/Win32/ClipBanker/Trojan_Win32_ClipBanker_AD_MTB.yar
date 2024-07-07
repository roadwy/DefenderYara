
rule Trojan_Win32_ClipBanker_AD_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 6e 74 69 64 65 74 65 63 74 20 62 72 6f 77 73 65 72 20 66 6f 72 20 67 65 6e 65 72 61 6c 20 70 75 72 70 6f 73 65 } //Antidetect browser for general purpose  3
		$a_80_1 = {44 65 6e 69 73 20 5a 68 69 74 6e 79 61 6b 6f 76 } //Denis Zhitnyakov  3
		$a_80_2 = {4e 45 54 57 4f 52 4b 5f 44 4f 57 4e } //NETWORK_DOWN  3
		$a_80_3 = {4f 72 65 61 6e 73 2e 76 78 64 } //Oreans.vxd  3
		$a_80_4 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 65 } //Software\Wine  3
		$a_80_5 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } //%userappdata%\RestartApp.exe  3
		$a_80_6 = {32 44 4a 53 32 } //2DJS2  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}