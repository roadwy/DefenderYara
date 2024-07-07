
rule Trojan_BAT_DarkTortilla_I_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 2b d8 28 90 01 01 00 00 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 74 90 01 01 00 00 1b 17 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}