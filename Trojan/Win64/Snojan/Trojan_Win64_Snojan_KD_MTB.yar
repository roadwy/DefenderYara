
rule Trojan_Win64_Snojan_KD_MTB{
	meta:
		description = "Trojan:Win64/Snojan.KD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 54 24 08 48 89 54 24 18 33 d2 48 8b c1 48 8b 4c 24 18 48 f7 f1 48 8b c2 48 8b 4c 24 40 0f be 04 01 8b 4c 24 04 33 c8 8b c1 48 63 0c 24 48 8b 54 24 30 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}