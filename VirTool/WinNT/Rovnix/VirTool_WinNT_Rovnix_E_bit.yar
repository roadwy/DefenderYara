
rule VirTool_WinNT_Rovnix_E_bit{
	meta:
		description = "VirTool:WinNT/Rovnix.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 c7 d1 ef a8 01 74 06 81 f7 90 01 04 d1 e9 4e 75 eb 90 00 } //1
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 61 00 66 00 65 00 42 00 72 00 61 00 69 00 6e 00 } //1 \Device\SafeBrain
		$a_01_2 = {5c 49 4e 4a 45 43 54 53 2e 53 59 53 } //1 \INJECTS.SYS
		$a_01_3 = {2a 00 5c 00 73 00 61 00 66 00 65 00 6d 00 6f 00 6e 00 5c 00 2a 00 2e 00 64 00 6c 00 6c 00 } //1 *\safemon\*.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}