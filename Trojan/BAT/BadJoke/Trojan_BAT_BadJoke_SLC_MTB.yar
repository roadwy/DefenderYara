
rule Trojan_BAT_BadJoke_SLC_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.SLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1c 72 86 04 00 70 a2 28 27 00 00 0a 0b 06 07 28 28 00 00 0a 00 06 28 29 00 00 0a 26 72 98 04 00 70 72 b0 04 00 70 72 d2 04 00 70 72 e6 04 00 70 28 04 00 00 06 00 02 28 2a 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}