
rule Trojan_BAT_RegRun_ANOH_MTB{
	meta:
		description = "Trojan:BAT/RegRun.ANOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {12 06 72 01 00 00 70 28 ?? ?? ?? 0a 13 05 06 11 04 11 05 a2 07 11 05 11 04 d2 6f ?? ?? ?? 0a 07 11 05 6f ?? ?? ?? 0a 11 04 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}