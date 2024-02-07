
rule Trojan_AndroidOS_Oscorp_A{
	meta:
		description = "Trojan:AndroidOS/Oscorp.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {48 49 44 44 45 4e 66 69 72 73 74 54 69 6d 65 } //01 00  HIDDENfirstTime
		$a_00_1 = {66 75 63 6b } //01 00  fuck
		$a_00_2 = {63 6f 6d 2e 63 6f 73 6d 6f 73 2e 73 74 61 72 77 61 72 7a } //00 00  com.cosmos.starwarz
	condition:
		any of ($a_*)
 
}