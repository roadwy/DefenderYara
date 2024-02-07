
rule TrojanSpy_AndroidOS_Wroba_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {7c 2a 63 61 6c 6c 45 6e 74 69 74 79 2a 7c } //01 00  |*callEntity*|
		$a_00_1 = {7c 2a 74 65 6c 45 6e 74 69 74 79 41 72 72 61 79 4c 69 73 74 2a 7c } //01 00  |*telEntityArrayList*|
		$a_00_2 = {2f 64 69 72 63 61 6c 6c } //01 00  /dircall
		$a_01_3 = {4e 65 74 77 6f 72 6b 5f 53 65 72 4d 6f 64 } //01 00  Network_SerMod
		$a_00_4 = {70 65 72 73 69 73 74 2e 74 78 74 } //01 00  persist.txt
		$a_00_5 = {63 6f 6e 74 61 63 74 73 2e 64 61 74 } //01 00  contacts.dat
		$a_00_6 = {2e 75 70 6c 6f 61 64 4e 75 6d 62 65 72 20 3d } //01 00  .uploadNumber =
		$a_00_7 = {75 70 64 61 74 65 2e 43 61 6c 6c 4c 6f 67 3a } //00 00  update.CallLog:
		$a_00_8 = {5d 04 00 00 } //d4 55 
	condition:
		any of ($a_*)
 
}