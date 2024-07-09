
rule Trojan_BAT_Bladabindi_BIL_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.BIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 06 11 0b 94 d6 11 07 11 0b 94 d6 20 00 01 00 00 5d 13 0a 11 06 11 0b 94 13 0e 11 06 11 0b 11 06 11 0a 94 9e 11 06 11 0a 11 0e 9e 12 0b 28 ?? ?? ?? 0a 11 0b 17 da 28 ?? ?? ?? 0a 26 00 11 0b 20 ff 00 00 00 fe 02 16 fe 01 13 0f 11 0f 2d ae } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}