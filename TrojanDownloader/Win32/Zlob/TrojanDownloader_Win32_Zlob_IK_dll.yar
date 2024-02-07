
rule TrojanDownloader_Win32_Zlob_IK_dll{
	meta:
		description = "TrojanDownloader:Win32/Zlob.IK!dll,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 74 66 78 71 6f 67 70 2e 44 4c 4c } //01 00  atfxqogp.DLL
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_00_2 = {5c 00 49 00 6d 00 70 00 6c 00 65 00 6d 00 65 00 6e 00 74 00 65 00 64 00 20 00 43 00 61 00 74 00 65 00 67 00 6f 00 72 00 69 00 65 00 73 00 } //01 00  \Implemented Categories
		$a_00_3 = {61 00 74 00 66 00 78 00 71 00 6f 00 67 00 70 00 54 00 4f 00 4f 00 4c 00 42 00 41 00 52 00 } //01 00  atfxqogpTOOLBAR
		$a_00_4 = {46 00 6f 00 72 00 63 00 65 00 52 00 65 00 6d 00 6f 00 76 00 65 00 } //0a 00  ForceRemove
		$a_00_5 = {8b 4c 24 04 f7 c1 03 00 00 00 74 24 8a 01 83 c1 01 84 c0 74 4e f7 c1 03 00 00 00 75 ef 05 00 00 00 00 8d a4 24 00 00 00 00 8d a4 24 00 00 00 00 8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04 a9 00 01 01 81 74 e8 } //00 00 
	condition:
		any of ($a_*)
 
}