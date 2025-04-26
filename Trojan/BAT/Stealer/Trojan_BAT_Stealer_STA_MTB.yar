
rule Trojan_BAT_Stealer_STA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.STA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 06 0a de 03 26 de 00 06 2c f1 06 28 05 00 00 06 0b 07 14 28 01 00 00 0a 2c 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}