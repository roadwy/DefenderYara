
rule Trojan_Win64_Qakbot_SA_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 90 01 01 eb 90 01 01 48 90 01 03 48 90 01 04 e9 90 01 04 8b c0 48 90 01 04 eb 90 01 01 33 c8 8b c1 eb 90 00 } //01 00 
		$a_03_1 = {ff c0 89 04 24 e9 90 01 04 c7 04 24 90 01 04 e9 90 01 04 8b 04 24 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}