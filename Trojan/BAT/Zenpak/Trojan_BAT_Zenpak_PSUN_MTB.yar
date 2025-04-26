
rule Trojan_BAT_Zenpak_PSUN_MTB{
	meta:
		description = "Trojan:BAT/Zenpak.PSUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 3b 00 00 70 11 0a 28 ?? 00 00 0a 72 73 00 00 70 72 79 00 00 70 6f ?? 00 00 0a 1f 5c 1f 2f 6f ?? 00 00 0a 13 0b 11 0b 28 ?? 00 00 0a 13 0b 06 11 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}