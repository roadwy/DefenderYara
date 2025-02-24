
rule Trojan_BAT_RedLine_BJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 26 06 6f ?? ?? 00 0a 0b 00 03 6f ?? ?? 00 0a 05 fe 04 16 fe 01 0c 08 2c ?? 2b ?? 02 03 04 07 05 28 ?? 00 00 06 00 00 06 6f } //2
		$a_03_1 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? ?? 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}