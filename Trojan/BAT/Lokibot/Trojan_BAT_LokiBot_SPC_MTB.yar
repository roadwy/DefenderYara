
rule Trojan_BAT_LokiBot_SPC_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 1c 2b 21 75 ?? ?? ?? 01 72 ?? ?? ?? 70 2b 1c 2b 21 2b 26 2b 2b 2b 30 14 14 2b 33 26 2a 28 ?? ?? ?? 0a 2b dd 28 08 00 00 06 2b d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}