
rule VirTool_WinNT_Lamechi_A{
	meta:
		description = "VirTool:WinNT/Lamechi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 14 80 f9 e9 75 0f 80 fa 2b 75 0a 80 bc 05 ?? ?? ?? ff e1 74 08 } //1
		$a_01_1 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be } //1
		$a_01_2 = {8d 7d f0 ab ab ab 68 48 02 00 00 ab } //1
		$a_03_3 = {80 3c 37 e8 75 17 8b 44 37 01 03 c7 8d 5c 30 05 53 ff 15 ?? ?? ?? ?? 84 c0 75 08 33 db 47 83 ff 40 72 dd } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}