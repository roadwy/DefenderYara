
rule Trojan_BAT_Jalapeno_SLWG_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SLWG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {1a 8d 08 00 00 01 13 04 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 1d 00 00 00 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}