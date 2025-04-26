
rule Trojan_BAT_Injuke_AMAI_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 13 05 06 11 05 6f ?? 00 00 0a 09 17 58 0d 09 08 6f ?? 00 00 0a 32 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}