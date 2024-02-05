
rule Trojan_Win64_Runner_EC_MTB{
	meta:
		description = "Trojan:Win64/Runner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f ba f1 1f 49 03 c9 8b 44 11 14 0f ba f0 1f 49 03 c1 8b 34 10 8b 6c 10 04 48 03 f2 74 c8 } //00 00 
	condition:
		any of ($a_*)
 
}