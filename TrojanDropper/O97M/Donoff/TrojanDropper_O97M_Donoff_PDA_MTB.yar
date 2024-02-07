
rule TrojanDropper_O97M_Donoff_PDA_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 73 68 6f 62 79 5f 6e 61 6d 65 3d 22 77 6c 74 68 67 61 6e 6b 79 22 66 6f 6c 64 65 72 5f 73 68 6f 62 79 5f 6e 61 6d 65 3d 65 6e 76 69 72 6f 6e 24 28 } //01 00  _shoby_name="wlthganky"folder_shoby_name=environ$(
		$a_01_1 = {3d 61 63 74 69 76 65 64 6f 63 75 6d 65 6e 74 64 6f 63 75 6d 65 6e 74 73 2e 6f 70 65 6e 70 61 74 68 5f 73 68 6f 62 79 5f 66 69 6c 65 64 6f 63 6e 65 77 2e 63 6c 6f 73 65 65 6e 64 73 75 62 } //01 00  =activedocumentdocuments.openpath_shoby_filedocnew.closeendsub
		$a_01_2 = {73 68 65 6c 6c 70 61 74 68 5f 73 68 6f 62 79 5f 66 69 6c 65 26 22 2e 65 78 22 26 22 65 22 2c 76 62 6e 6f 72 6d 61 6c 6e 6f 66 6f 63 75 73 63 61 6c 6c 73 68 6f 62 79 5f 64 6f 63 6c } //01 00  shellpath_shoby_file&".ex"&"e",vbnormalnofocuscallshoby_docl
		$a_01_3 = {66 6f 72 69 3d 30 74 6f 75 62 6f 75 6e 64 28 61 77 72 31 73 68 6f 62 79 5f 73 29 2d 6c 62 6f 75 6e 64 28 61 77 72 31 73 68 6f 62 79 5f 73 29 73 68 6f 62 79 5f 62 77 65 79 74 28 69 29 3d 61 77 72 31 73 68 6f 62 79 5f 73 28 69 29 6e 65 78 74 6f 70 65 6e 70 61 74 68 5f 73 68 6f 62 79 5f 66 69 6c 65 26 22 2e 65 22 26 22 78 65 } //00 00  fori=0toubound(awr1shoby_s)-lbound(awr1shoby_s)shoby_bweyt(i)=awr1shoby_s(i)nextopenpath_shoby_file&".e"&"xe
	condition:
		any of ($a_*)
 
}