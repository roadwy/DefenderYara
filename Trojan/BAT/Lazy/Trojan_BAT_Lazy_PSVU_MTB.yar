
rule Trojan_BAT_Lazy_PSVU_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 00 28 ?? 00 00 0a 72 9d 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 73 ?? 00 00 0a 0b 07 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}