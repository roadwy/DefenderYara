
rule Trojan_BAT_Rozena_BGN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.BGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 8e 69 0a 7e 11 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 0b 16 07 06 28 ?? 00 00 0a 7e 11 00 00 0a 16 07 7e 11 00 00 0a 16 7e 11 00 00 0a 28 ?? 00 00 06 15 28 ?? 00 00 06 26 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}