
rule Trojan_AndroidOS_RewardSteal_H{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.H,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 64 6a 73 73 6b 66 64 6b 73 66 6b 73 64 6b 66 6a 6b 6b 73 68 6b 66 68 6b 73 68 6b } //01 00  sdjsskfdksfksdkfjkkshkfhkshk
		$a_01_1 = {63 6f 6d 2e 61 62 63 38 39 38 64 2e 77 65 62 6d 61 73 74 65 72 } //01 00  com.abc898d.webmaster
		$a_00_2 = {2b 39 31 38 36 33 37 35 37 39 37 34 31 } //00 00  +918637579741
	condition:
		any of ($a_*)
 
}