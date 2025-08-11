
rule TrojanSpy_BAT_XWorm_AOX_MTB{
	meta:
		description = "TrojanSpy:BAT/XWorm.AOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 28 ?? 00 00 0a 13 06 28 ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 07 06 28 ?? 00 00 0a 13 08 28 ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 09 28 ?? 00 00 0a 13 0a 09 28 ?? 00 00 0a 13 0b 19 8d ?? 00 00 01 13 0d 11 0d 16 11 0a a2 11 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}