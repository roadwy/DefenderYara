
rule Trojan_BAT_AmsiPatch_DB_MTB{
	meta:
		description = "Trojan:BAT/AmsiPatch.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 d3 0b 06 28 ?? ?? ?? ?? 0d 00 08 17 58 0c 08 06 20 2c 01 00 00 20 b8 0b 00 00 6f ?? ?? ?? ?? fe 04 13 04 11 04 2d d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}