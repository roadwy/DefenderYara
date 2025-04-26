
rule Trojan_BAT_Stealer_PAFP_MTB{
	meta:
		description = "Trojan:BAT/Stealer.PAFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 63 d1 13 14 11 11 11 08 91 13 25 11 11 11 08 11 25 11 22 61 19 11 1b 58 61 11 30 61 d2 9c 11 08 17 58 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}