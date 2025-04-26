
rule Trojan_BAT_Marsilia_APN_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.APN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 07 72 15 00 00 70 6f ?? ?? ?? 0a 07 72 29 00 00 70 6f ?? ?? ?? 0a 07 72 e4 03 00 70 6f ?? ?? ?? 0a 07 72 f8 03 00 70 6f ?? ?? ?? 0a 07 72 1c 04 00 70 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}