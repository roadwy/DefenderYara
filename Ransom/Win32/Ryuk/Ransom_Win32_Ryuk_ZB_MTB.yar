
rule Ransom_Win32_Ryuk_ZB_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 65 66 61 75 6c 74 20 55 73 65 72 5c 66 69 6e 69 73 68 } //01 00  Default User\finish
		$a_00_1 = {66 69 72 65 66 6f 78 63 6f 6e 66 69 67 } //03 00  firefoxconfig
		$a_01_2 = {55 00 4e 00 49 00 51 00 55 00 45 00 5f 00 49 00 44 00 5f 00 44 00 4f 00 5f 00 4e 00 4f 00 54 00 5f 00 52 00 45 00 4d 00 4f 00 56 00 45 00 } //03 00  UNIQUE_ID_DO_NOT_REMOVE
		$a_03_3 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 d0 8d 04 92 03 c0 2b c8 83 f9 09 7e 90 01 01 83 c1 57 eb 90 01 01 83 c1 30 90 00 } //01 00 
		$a_00_4 = {74 00 62 00 69 00 72 00 64 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //01 00  tbirdconfig
		$a_00_5 = {4e 00 74 00 72 00 74 00 73 00 63 00 61 00 6e 00 } //00 00  Ntrtscan
		$a_00_6 = {5d 04 00 00 ef } //44 04 
	condition:
		any of ($a_*)
 
}