
rule Trojan_BAT_Zusy_AI_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 3e 00 00 04 20 36 fc 3a 26 20 3a b3 91 9f 61 20 03 00 00 00 63 20 e1 69 35 f7 61 7d 4d 00 00 04 20 3e 00 00 00 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}