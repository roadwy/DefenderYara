
rule Trojan_BAT_Basic_KAA_MTB{
	meta:
		description = "Trojan:BAT/Basic.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 32 01 00 06 fe 0e 01 00 28 33 01 00 06 28 34 01 00 06 28 35 01 00 06 61 28 36 01 00 06 40 10 00 00 00 28 37 01 00 06 fe 0e 01 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}