
rule Trojan_Win64_CobaltStrike_PAC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PAC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 1f 00 0f b6 c1 2a c3 32 01 32 c2 88 01 48 03 ce 49 3b c9 72 ed 49 ff c0 48 ff c7 49 ff cb 75 d2 45 33 c9 4c 8b c3 } //00 00 
	condition:
		any of ($a_*)
 
}