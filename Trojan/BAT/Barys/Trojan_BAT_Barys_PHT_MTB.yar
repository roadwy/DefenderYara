
rule Trojan_BAT_Barys_PHT_MTB{
	meta:
		description = "Trojan:BAT/Barys.PHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 0b 07 2a } //6
		$a_03_1 = {0a 25 17 6f ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0f 00 28 ?? 00 00 0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0b 07 2a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}