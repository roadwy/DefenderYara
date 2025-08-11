
rule Trojan_BAT_DarkTortilla_SL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 0c 11 0e 11 0c 6c 11 0e 6c 28 06 01 00 0a 11 0c 11 0e d6 17 d6 6c 5b 28 07 01 00 0a 11 0e 17 d6 13 0e 11 0e 11 0d 31 d5 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}