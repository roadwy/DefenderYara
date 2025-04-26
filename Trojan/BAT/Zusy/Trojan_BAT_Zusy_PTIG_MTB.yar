
rule Trojan_BAT_Zusy_PTIG_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PTIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 55 20 00 70 07 72 8f 20 00 70 6f 4d 00 00 0a 28 ?? 00 00 0a 00 73 84 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}