
rule Trojan_BAT_Tiny_GVA_MTB{
	meta:
		description = "Trojan:BAT/Tiny.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 28 37 00 00 0a 2d 0c 06 08 6f 38 00 00 0a 6f 39 00 00 0a 07 6f 3a 00 00 0a 25 0c 2d e2 06 0d de 0a 07 2c 06 07 6f 27 00 00 0a dc 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}