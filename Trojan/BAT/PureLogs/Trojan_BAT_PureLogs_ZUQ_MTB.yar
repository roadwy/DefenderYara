
rule Trojan_BAT_PureLogs_ZUQ_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.ZUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {7a 11 02 16 28 ?? 00 00 0a 13 03 38 ?? 00 00 00 00 20 00 10 00 00 8d ?? 00 00 01 13 05 38 ?? 00 00 00 fe 0c 06 00 45 01 00 00 00 3a 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 38 ?? 00 00 00 11 01 11 05 } //6
		$a_03_1 = {16 11 09 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 0a 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 09 16 3d ?? ff ff ff 38 00 00 00 00 dd } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}