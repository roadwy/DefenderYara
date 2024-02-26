
rule Trojan_Win64_CobaltStrike_PABK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b d1 41 8b c0 b9 40 00 00 00 83 e0 3f 2b c8 33 c0 48 d3 c8 49 33 c0 48 39 05 8e 9e 0c 00 75 12 } //00 00 
	condition:
		any of ($a_*)
 
}