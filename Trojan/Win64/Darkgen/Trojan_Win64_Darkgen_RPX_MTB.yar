
rule Trojan_Win64_Darkgen_RPX_MTB{
	meta:
		description = "Trojan:Win64/Darkgen.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e3 07 c1 e1 06 49 83 c7 04 c1 e3 12 83 e2 3f 09 ca 09 da 89 d1 81 f9 ff ff 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}