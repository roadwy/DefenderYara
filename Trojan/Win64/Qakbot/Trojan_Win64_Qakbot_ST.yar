
rule Trojan_Win64_Qakbot_ST{
	meta:
		description = "Trojan:Win64/Qakbot.ST,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 69 63 6b 65 6e 66 72 69 65 64 } //01 00  chickenfried
		$a_01_1 = {65 6c 65 63 74 72 69 63 6d 61 64 6e 65 73 73 } //01 00  electricmadness
		$a_01_2 = {62 75 73 69 6e 65 73 73 2e 64 6f 63 } //01 00  business.doc
		$a_01_3 = {3a 2f 2f 00 50 4f 53 54 } //01 00  ⼺/佐呓
		$a_01_4 = {00 68 76 73 69 00 } //01 00  栀獶i
		$a_01_5 = {65 6e 64 6c 65 73 73 00 61 70 70 65 61 72 } //00 00  湥汤獥s灡数牡
		$a_00_6 = {5d 04 00 00 } //30 56 
	condition:
		any of ($a_*)
 
}