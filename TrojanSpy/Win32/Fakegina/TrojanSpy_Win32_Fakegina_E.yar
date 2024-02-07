
rule TrojanSpy_Win32_Fakegina_E{
	meta:
		description = "TrojanSpy:Win32/Fakegina.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 6c 78 4c 6f 67 67 65 64 4f 75 74 53 41 53 00 6d 73 67 69 6e 61 2e 64 6c 6c 90 02 05 5c 42 72 30 57 4d 69 6e 55 53 65 72 53 2e 44 4c 4c 90 00 } //01 00 
		$a_01_1 = {4f 00 6c 00 64 00 50 00 61 00 73 00 73 00 20 00 3d 00 20 00 25 00 73 00 } //01 00  OldPass = %s
		$a_01_2 = {44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 20 00 3d 00 20 00 25 00 73 00 } //00 00  Domain  = %s
	condition:
		any of ($a_*)
 
}