
rule Trojan_Win64_CobaltStrike_AUS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AUS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 0c 00 33 8f 90 01 04 48 8b 87 90 01 04 41 89 0c 00 48 8d 0d 90 01 04 48 c7 c0 90 01 04 48 2b c1 48 01 87 90 01 04 48 8b 87 90 01 04 48 39 47 40 77 90 00 } //01 00 
		$a_03_1 = {ff c6 01 87 90 01 04 49 83 c0 04 48 8b 47 90 01 01 8b 50 90 01 01 41 2b d1 48 63 c6 48 c1 ea 02 48 3b c2 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}