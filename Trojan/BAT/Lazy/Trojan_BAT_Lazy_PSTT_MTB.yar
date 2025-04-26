
rule Trojan_BAT_Lazy_PSTT_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 72 4b 00 00 70 7e 01 00 00 04 1b 1f 19 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 13 04 11 04 2c 03 00 2b ce } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}