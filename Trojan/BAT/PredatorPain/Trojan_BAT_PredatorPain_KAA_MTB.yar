
rule Trojan_BAT_PredatorPain_KAA_MTB{
	meta:
		description = "Trojan:BAT/PredatorPain.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 1c 13 04 2b b7 0e 04 05 61 1f 77 59 06 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}