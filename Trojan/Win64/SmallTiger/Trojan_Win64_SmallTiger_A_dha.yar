
rule Trojan_Win64_SmallTiger_A_dha{
	meta:
		description = "Trojan:Win64/SmallTiger.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {3c 11 00 75 eb 48 8b 4c 24 90 01 01 33 d2 48 f7 f1 48 8b c2 48 8b 4c 24 90 01 01 0f b6 14 01 48 8d 8c 24 90 01 04 e8 90 01 04 eb 12 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}