
rule Trojan_BAT_Rozena_SPT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 13 00 00 0a 0d 16 13 04 16 08 8e 69 20 90 01 03 00 1f 40 28 90 01 03 06 13 05 08 16 11 05 6e 28 90 01 03 0a 08 8e 69 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}