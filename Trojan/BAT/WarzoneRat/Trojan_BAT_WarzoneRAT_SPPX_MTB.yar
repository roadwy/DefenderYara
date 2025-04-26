
rule Trojan_BAT_WarzoneRAT_SPPX_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRAT.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 8e 2c 04 17 0a 2b 0d 11 04 17 58 13 04 11 04 09 8e 69 32 de } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}