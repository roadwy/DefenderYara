
rule Trojan_BAT_Stealer_PAFO_MTB{
	meta:
		description = "Trojan:BAT/Stealer.PAFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 63 d1 13 14 11 11 11 0a 91 13 20 11 11 11 0a 11 20 11 26 61 11 1c 19 58 61 11 31 61 d2 9c 11 20 13 1c 17 11 0a 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}