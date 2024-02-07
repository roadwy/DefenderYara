
rule Trojan_AndroidOS_FakeInstSms_G{
	meta:
		description = "Trojan:AndroidOS/FakeInstSms.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 70 2e 73 65 6c 65 72 69 6e 6f 2e 62 72 65 64 6e 6f } //01 00  jp.selerino.bredno
		$a_00_1 = {70 61 72 73 6e 65 77 64 61 74 61 61 6e 64 73 65 6e 64 } //01 00  parsnewdataandsend
		$a_00_2 = {73 65 74 72 6f 6f 6c 73 64 69 73 70 6c 61 79 } //01 00  setroolsdisplay
		$a_00_3 = {70 72 76 6c 2e 74 78 74 } //01 00  prvl.txt
		$a_00_4 = {73 65 6e 64 53 4d 53 6b 61 68 69 } //01 00  sendSMSkahi
		$a_00_5 = {45 53 4c 49 41 42 4f 4e 45 4e 54 54 55 50 49 54 } //00 00  ESLIABONENTTUPIT
		$a_00_6 = {5d 04 00 } //00 d5 
	condition:
		any of ($a_*)
 
}