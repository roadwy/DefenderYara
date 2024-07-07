
rule Trojan_BAT_Zusy_PTIA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 11 04 16 08 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 11 04 16 11 04 8e 69 6f 54 00 00 0a 13 05 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}