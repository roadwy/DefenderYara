
rule Trojan_BAT_DarkTortilla_Q_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.Q!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 d0 90 01 01 00 00 1b 28 90 01 01 00 00 0a a2 14 28 90 01 01 00 00 0a 14 17 8d 90 01 01 00 00 01 25 16 11 08 74 90 01 01 00 00 1b 11 07 17 da 9a a2 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a a2 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}