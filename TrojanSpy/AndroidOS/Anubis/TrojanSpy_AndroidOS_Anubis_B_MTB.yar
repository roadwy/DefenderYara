
rule TrojanSpy_AndroidOS_Anubis_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Anubis.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 20 41 63 74 69 76 69 74 79 20 49 6e 6a 65 63 74 } //01 00  Start Activity Inject
		$a_00_1 = {47 72 61 62 62 65 72 20 63 61 72 64 73 20 6d 69 6e 69 } //01 00  Grabber cards mini
		$a_00_2 = {66 61 66 61 2e 70 68 70 3f 66 3d } //01 00  fafa.php?f=
		$a_02_3 = {2f 6f 31 6f 2f 61 90 02 03 2e 70 68 70 90 00 } //01 00 
		$a_00_4 = {73 74 72 5f 70 75 73 68 5f 66 69 73 68 } //01 00  str_push_fish
		$a_01_5 = {53 74 61 72 74 65 64 20 66 6f 72 20 44 69 73 61 62 6c 65 20 50 6c 61 79 20 50 72 6f 74 65 63 74 20 41 63 74 69 6f 6e } //00 00  Started for Disable Play Protect Action
	condition:
		any of ($a_*)
 
}