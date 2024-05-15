
rule Trojan_Win64_CobaltStrike_CCHU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {bd 6c 04 00 00 8b 44 24 70 31 e8 b9 90 01 04 44 89 f2 44 89 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}