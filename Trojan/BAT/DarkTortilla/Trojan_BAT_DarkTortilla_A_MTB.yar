
rule Trojan_BAT_DarkTortilla_A_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 16 16 02 17 8d ?? 00 00 01 25 16 11 0b 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 28 ?? 01 00 0a 16 16 11 0e 11 0d 18 28 ?? 01 00 06 18 28 ?? 01 00 06 b4 9c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}