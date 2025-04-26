
rule Trojan_BAT_Lazy_AO_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 1b 8d 24 00 00 01 0c 02 28 ?? ?? ?? 06 15 16 6f ?? ?? ?? 0a 26 02 28 ?? ?? ?? 06 08 16 1b 16 6f ?? ?? ?? 0a 0b 1a 8d 24 00 00 01 25 16 08 16 91 9c 25 17 08 17 91 9c 25 18 08 18 91 9c 25 19 08 19 91 9c 16 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}