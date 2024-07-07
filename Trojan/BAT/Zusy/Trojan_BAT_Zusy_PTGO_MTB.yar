
rule Trojan_BAT_Zusy_PTGO_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 07 8e 69 59 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 02 08 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}