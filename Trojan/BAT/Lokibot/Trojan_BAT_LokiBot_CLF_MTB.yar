
rule Trojan_BAT_LokiBot_CLF_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 f8 02 00 70 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 17 8d ?? ?? ?? ?? 25 16 1f 2d 9d 6f ?? ?? ?? ?? 0b 07 8e } //5
		$a_03_1 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? ?? d2 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d db } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}