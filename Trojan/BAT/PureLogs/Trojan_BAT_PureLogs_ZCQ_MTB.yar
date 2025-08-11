
rule Trojan_BAT_PureLogs_ZCQ_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.ZCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {7a 11 02 16 28 ?? 00 00 0a 13 03 38 ?? ff ff ff 73 ?? 00 00 0a 7a 11 00 16 73 ?? 00 00 0a 13 04 38 ?? ff ff ff 11 01 6f ?? 00 00 0a 25 8e 69 11 03 3b ?? 00 00 00 73 ?? 00 00 0a 7a 13 07 38 ?? 00 00 00 dd } //6
		$a_03_1 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 ?? 00 00 00 38 ?? 00 00 00 38 e5 ff ff ff 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}