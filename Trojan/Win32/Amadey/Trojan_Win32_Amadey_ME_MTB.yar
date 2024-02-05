
rule Trojan_Win32_Amadey_ME_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {66 f7 c5 df 1a 33 cb e9 ec b7 53 00 ff e6 66 85 e7 66 3b f5 81 c7 08 00 00 00 89 08 81 ee 04 00 00 00 66 c1 f1 6b 0f ab f9 66 c1 e1 37 8b 0e f8 } //05 00 
		$a_01_1 = {81 ff 01 44 f9 f8 81 e9 51 1c f4 0f 84 f2 66 f7 c4 cc 0e 0f c9 33 d9 e9 a6 f2 0b 00 f7 d9 f9 33 d9 03 f1 56 c3 0f 31 f8 8d bf f8 ff ff ff 66 f7 } //02 00 
		$a_01_2 = {e0 00 02 01 0b 01 0e 18 00 8c 02 00 00 0c 0c } //02 00 
		$a_01_3 = {2e 76 6d 70 30 } //02 00 
		$a_01_4 = {2e 76 6d 70 32 } //00 00 
	condition:
		any of ($a_*)
 
}