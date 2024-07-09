
rule Trojan_BAT_Injuke_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 73 ?? 00 00 0a 09 07 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 2b 16 fe 01 13 } //1
		$a_03_1 = {02 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}