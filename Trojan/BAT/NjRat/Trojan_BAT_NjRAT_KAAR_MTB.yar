
rule Trojan_BAT_NjRAT_KAAR_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 02 11 05 91 08 61 06 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05 00 07 17 d6 0b 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}