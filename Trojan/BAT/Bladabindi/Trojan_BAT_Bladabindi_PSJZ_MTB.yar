
rule Trojan_BAT_Bladabindi_PSJZ_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 2b 00 00 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 77 00 00 70 15 16 28 ?? ?? ?? 0a 80 0b 00 00 04 7e 0b 00 00 04 17 9a 28 ?? ?? ?? 0a 72 e5 00 00 70 28 11 00 00 06 80 0c 00 00 04 20 e4 04 00 00 28 ?? ?? ?? 0a 7e 0b 00 00 04 17 9a 6f ?? ?? ?? 0a 26 7e 0c 00 00 04 28 12 00 00 06 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}