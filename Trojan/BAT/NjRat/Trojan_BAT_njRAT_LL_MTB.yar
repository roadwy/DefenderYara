
rule Trojan_BAT_njRAT_LL_MTB{
	meta:
		description = "Trojan:BAT/njRAT.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 02 11 05 91 08 11 05 09 5d 91 61 9c 00 2b 06 9c ?? ?? ?? ?? ?? 11 05 17 d6 13 05 2b 06 9c ?? ?? ?? ?? ?? 11 05 11 08 31 02 2b 09 2b 99 13 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}