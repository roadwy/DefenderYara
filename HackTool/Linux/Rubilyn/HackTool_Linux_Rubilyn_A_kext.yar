
rule HackTool_Linux_Rubilyn_A_kext{
	meta:
		description = "HackTool:Linux/Rubilyn.A!kext,SIGNATURE_TYPE_MACHOHSTR_EXT,16 00 16 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 ff c6 4c 89 f7 e8 00 00 00 00 49 89 c7 4c 89 eb 8a 0b 31 c0 84 c9 74 1e 4c 8d 6b 01 44 38 e1 75 ec } //10
		$a_01_1 = {31 c0 89 c3 4c 89 7d c8 4c 63 fb 43 8a 04 3e 48 8b 4d c8 42 32 04 29 0f be c0 89 45 d4 } //10
		$a_01_2 = {72 75 62 69 6c 79 6e } //2 rubilyn
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=22
 
}