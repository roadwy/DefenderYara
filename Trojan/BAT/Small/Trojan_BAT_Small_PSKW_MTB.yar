
rule Trojan_BAT_Small_PSKW_MTB{
	meta:
		description = "Trojan:BAT/Small.PSKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 57 00 00 0a 28 ?? ?? ?? 0a 18 16 15 28 ?? ?? ?? 0a 26 28 06 00 00 06 6f ?? ?? ?? 0a 72 ee 01 00 70 72 32 02 00 70 6f ?? ?? ?? 0a 00 28 06 00 00 06 6f 5a 00 00 0a 72 64 02 00 70 72 a4 02 00 70 6f ?? ?? ?? 0a 00 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}