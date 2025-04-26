
rule Trojan_BAT_Zusy_PTCH_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 97 00 00 70 0a 02 06 28 ?? 00 00 06 00 72 d5 00 00 70 0b 02 07 28 ?? 00 00 06 00 00 de 1b } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}