
rule Trojan_BAT_Bladabindi_EAU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.EAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 9a 6f 5a 00 00 0a 02 16 28 33 00 00 0a 16 33 04 06 08 9a 2a 08 17 d6 0c 08 09 31 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}