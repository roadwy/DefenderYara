
rule Trojan_BAT_Jalapeno_BD_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 13 0a 28 8a 01 00 06 7e 94 00 00 0a 28 98 00 00 0a 13 0e 7e 6a 00 00 04 28 2b 01 00 06 0a 14 0b 14 0c 14 0d 7e 89 00 00 04 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}