
rule Trojan_BAT_Netwire_AMFA_MTB{
	meta:
		description = "Trojan:BAT/Netwire.AMFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 16 f8 00 00 0c 2b 11 06 08 20 00 01 00 00 28 ?? ?? ?? 06 0a 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}