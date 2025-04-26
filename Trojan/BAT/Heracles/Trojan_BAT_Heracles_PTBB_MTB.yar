
rule Trojan_BAT_Heracles_PTBB_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PTBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 09 00 00 04 8c 23 00 00 01 28 ?? 00 00 0a 02 28 ?? 00 00 0a 6f 31 00 00 0a 0b 7e 05 00 00 04 6f 32 00 00 0a 80 04 00 00 04 7e 04 00 00 04 07 16 07 8e 69 6f 33 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}