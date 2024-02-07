
rule Trojan_Win32_Sabsik_RM_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 39 8e e3 38 f7 e1 8b c6 c1 ea 02 8d 0c d2 03 c9 2b c1 0f b6 80 90 01 04 30 86 90 01 04 83 c6 02 81 fe 7e 07 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Sabsik_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Sabsik.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 6e 61 67 65 6d 65 6e 74 64 69 63 6b 73 75 62 6d 65 6e 75 64 65 74 65 63 74 73 71 75 69 63 6b 6c 79 72 43 } //01 00  managementdicksubmenudetectsquicklyrC
		$a_01_1 = {71 43 69 6e 73 74 61 6c 6c 6f 74 6f 70 67 75 6e 43 61 6e 64 66 6f 72 } //01 00  qCinstallotopgunCandfor
		$a_01_2 = {75 78 70 6c 75 67 69 6e 30 70 6f 69 6e 74 73 2e 36 34 32 2e 31 6f 76 65 72 73 69 6f 6e } //01 00  uxplugin0points.642.1oversion
		$a_01_3 = {46 54 54 54 52 2e 70 64 62 } //01 00  FTTTR.pdb
		$a_00_4 = {44 00 6d 00 65 00 74 00 72 00 69 00 63 00 73 00 37 00 6d 00 61 00 6a 00 6f 00 72 00 6e 00 31 00 6c 00 62 00 36 00 35 00 34 00 33 00 32 00 31 00 } //00 00  Dmetrics7majorn1lb654321
	condition:
		any of ($a_*)
 
}