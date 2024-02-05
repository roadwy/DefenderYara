
rule Trojan_AndroidOS_Wipelock_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Wipelock.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 65 74 6d 69 6d 65 74 79 70 65 66 72 6f 6d 65 78 74 65 6e 73 69 6f 6e } //01 00 
		$a_00_1 = {61 64 64 53 4d 53 49 6e 74 6f 49 6e 62 6f 78 } //01 00 
		$a_00_2 = {69 73 43 61 6c 6c 66 72 6f 6d 50 61 73 73 77 6f 72 64 53 63 72 65 65 6e } //01 00 
		$a_00_3 = {6b 65 65 70 52 75 6e 6e 69 6e 67 41 63 74 69 76 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}