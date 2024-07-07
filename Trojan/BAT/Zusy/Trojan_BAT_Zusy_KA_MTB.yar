
rule Trojan_BAT_Zusy_KA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 1a 58 91 06 d2 61 d2 9c 06 17 62 06 1f 1f 63 60 0a 08 17 58 0c 08 07 8e 69 32 e1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}