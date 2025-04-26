
rule Trojan_BAT_Umbral_ASZ_MTB{
	meta:
		description = "Trojan:BAT/Umbral.ASZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 2c 06 07 9a 0c 7e 4a 05 00 04 08 6f d0 02 00 0a 6f 05 02 00 0a 28 56 00 00 2b 2c 0d 08 6f d1 02 00 0a de 05 26 17 0d de 0c 07 17 58 0b 07 06 8e 69 32 ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}