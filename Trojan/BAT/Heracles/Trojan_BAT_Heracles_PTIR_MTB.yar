
rule Trojan_BAT_Heracles_PTIR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 4d 00 00 0a 25 18 6f 4e 00 00 0a 6f 4f 00 00 0a 07 16 07 8e 69 6f 50 00 00 0a 0c de 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}