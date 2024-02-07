
rule Trojan_AndroidOS_Joker_pb{
	meta:
		description = "Trojan:AndroidOS/Joker.pb,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 63 6f 6f 6c 72 69 6e 67 74 69 6e 67 2e 72 69 6e 67 74 6f 6e 65 73 6d 61 6b 65 72 } //02 00  com.coolringting.ringtonesmaker
		$a_00_1 = {4b 78 73 62 48 42 70 39 52 6c 39 55 57 6c 31 63 58 56 30 52 48 78 5a 6a 55 31 70 4b 43 79 63 49 51 42 39 45 4f 68 77 48 } //00 00  KxsbHBp9Rl9UWl1cXV0RHxZjU1pKCycIQB9EOhwH
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}