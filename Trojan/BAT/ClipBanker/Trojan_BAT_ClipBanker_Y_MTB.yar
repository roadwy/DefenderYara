
rule Trojan_BAT_ClipBanker_Y_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {1b 11 06 9a 28 ?? 00 00 0a 13 07 28 ?? 02 00 06 74 ?? 00 00 01 11 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 08 20 ?? ?? ?? 00 28 ?? 00 00 0a 8c ?? 00 00 01 13 09 11 08 75 ?? 00 00 01 6f ?? 00 00 0a 8c ?? 00 00 01 11 09 16 28 ?? 00 00 0a 13 0a 11 0a 2c 31 11 09 28 ?? 00 00 0a 14 28 ?? ?? 00 06 28 ?? ?? 00 06 11 08 74 ?? 00 00 01 28 ?? 02 00 06 74 ?? 00 00 1b 16 11 09 28 } //2
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}