
rule Trojan_BAT_Bladabindi_KA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 42 2b 1f 2b 41 2b 42 2b 43 08 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 16 2d 0d 08 17 25 2c 05 58 0c 08 06 8e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}