
rule Trojan_BAT_Androm_SLU_MTB{
	meta:
		description = "Trojan:BAT/Androm.SLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 09 00 00 06 0a 73 0f 00 00 0a 25 02 06 28 08 00 00 06 6f 10 00 00 0a 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}