
rule Trojan_Win64_CobaltStrike_MN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 89 c1 ba 01 00 00 00 81 e1 ff 01 00 00 49 89 c8 48 d3 e2 49 c1 f8 06 4a 85 54 c0 10 0f 95 c2 88 d0 48 83 c4 28 } //00 00 
	condition:
		any of ($a_*)
 
}