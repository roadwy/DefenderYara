
rule Trojan_BAT_Stealer_BAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 03 61 d2 9c 06 17 58 0a 06 02 8e 69 32 ed 02 73 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}