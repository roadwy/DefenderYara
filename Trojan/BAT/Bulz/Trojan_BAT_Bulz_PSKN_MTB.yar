
rule Trojan_BAT_Bulz_PSKN_MTB{
	meta:
		description = "Trojan:BAT/Bulz.PSKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 ab 24 00 70 02 7b 54 01 00 04 6f 30 01 00 06 28 1c 01 00 0a 28 ?? ?? ?? 0a 0d 07 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 02 07 28 6f 01 00 06 0c 02 7b 54 01 00 04 08 28 ?? ?? ?? 0a 6f 33 01 00 06 26 de 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}