
rule Trojan_BAT_Zusy_PSTS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 99 02 00 70 28 ?? 00 00 0a 06 72 a7 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 28 ?? 00 00 0a 26 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}