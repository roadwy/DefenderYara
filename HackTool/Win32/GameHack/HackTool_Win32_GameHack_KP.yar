
rule HackTool_Win32_GameHack_KP{
	meta:
		description = "HackTool:Win32/GameHack.KP,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6c 61 72 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 43 47 5f 4c 6f 61 64 65 72 5c 43 47 5f 4c 6f 61 64 65 72 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 43 47 5f 4c 6f 61 64 65 72 2e 70 64 62 } //1 malar\Visual Studio\CG_Loader\CG_Loader\obj\x86\Release\CG_Loader.pdb
		$a_01_1 = {43 47 5f 4c 6f 61 64 65 72 } //1 CG_Loader
		$a_01_2 = {50 55 42 47 5f 4c 69 74 65 5f 48 61 63 6b } //1 PUBG_Lite_Hack
		$a_01_3 = {57 4f 4c 46 54 55 5f 4d 75 6c 74 69 68 61 63 6b } //1 WOLFTU_Multihack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}