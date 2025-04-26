
rule Trojan_BAT_Remcos_ASO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ASO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 20 00 00 0a 6f 21 00 00 0a 28 22 00 00 0a 0c de 17 26 20 d0 07 00 00 28 23 00 00 0a de 00 06 17 58 0a 06 1b 32 c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}