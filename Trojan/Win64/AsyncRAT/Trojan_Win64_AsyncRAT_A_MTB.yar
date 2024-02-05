
rule Trojan_Win64_AsyncRAT_A_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 48 89 84 24 90 01 04 48 63 4c 24 90 01 01 33 d2 48 8b c1 b9 90 01 04 48 f7 f1 48 8b c2 48 0f be 84 04 90 01 04 48 89 84 24 90 01 04 48 8d 8c 24 90 00 } //02 00 
		$a_03_1 = {48 8b 8c 24 90 01 04 48 03 c8 48 8b c1 48 8b 8c 24 90 01 04 48 33 c8 48 8b c1 48 63 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}