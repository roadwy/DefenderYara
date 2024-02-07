
rule Trojan_AndroidOS_FakeAV_A_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeAV.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 61 6b 65 41 63 74 69 76 69 74 79 } //01 00  FakeActivity
		$a_00_1 = {62 6c 6f 63 6b 50 68 6f 6e 65 73 } //01 00  blockPhones
		$a_01_2 = {4e 45 57 5f 4f 55 54 47 4f 49 4e 47 5f 43 41 4c 4c } //01 00  NEW_OUTGOING_CALL
		$a_00_3 = {72 65 71 75 65 73 74 4c 6f 63 61 74 69 6f 6e 55 70 64 61 74 65 73 } //01 00  requestLocationUpdates
		$a_00_4 = {64 6f 77 6e 6c 6f 61 64 73 2f 6c 69 73 74 2e 74 78 74 } //01 00  downloads/list.txt
		$a_01_5 = {56 49 52 55 53 21 21 21 } //01 00  VIRUS!!!
		$a_00_6 = {61 6e 74 69 76 69 72 75 73 2f 70 72 6f } //00 00  antivirus/pro
		$a_00_7 = {5d 04 00 00 71 94 } //04 80 
	condition:
		any of ($a_*)
 
}