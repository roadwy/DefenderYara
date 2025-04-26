
rule Trojan_BAT_Rozena_GNT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 16 13 08 16 16 11 06 7e ?? ?? ?? ?? 16 12 08 28 } //5
		$a_03_1 = {11 05 8e 69 20 00 10 00 00 1a 28 ?? ?? ?? 06 13 06 11 05 16 11 06 11 05 8e 69 28 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}