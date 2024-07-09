
rule Trojan_BAT_Injuke_GNF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 07 16 6f ?? ?? ?? 0a 13 0a 12 0a 28 ?? ?? ?? 0a 13 08 11 06 11 08 6f ?? ?? ?? 0a 07 17 58 0b 07 11 05 6f ?? ?? ?? 0a 32 d5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}