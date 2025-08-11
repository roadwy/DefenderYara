
rule Trojan_BAT_Zusy_SM{
	meta:
		description = "Trojan:BAT/Zusy.SM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 07 91 07 03 28 7b 00 00 06 9c 07 17 d6 0b 07 06 31 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}