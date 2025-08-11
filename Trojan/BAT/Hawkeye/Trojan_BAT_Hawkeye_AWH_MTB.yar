
rule Trojan_BAT_Hawkeye_AWH_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 16 7e 03 00 00 04 06 7e 03 00 00 04 06 91 1f ?? 61 d2 9c 06 17 58 0a 06 7e 03 00 00 04 8e 69 32 e0 } //1
		$a_03_1 = {16 0c 2b 33 28 ?? 00 00 06 06 07 9a 6f ?? 00 00 0a 74 ?? 00 00 1b 0d 09 16 7e ?? 00 00 04 08 09 8e 69 17 59 28 ?? 00 00 0a 08 09 8e 69 58 0c 08 17 59 0c 07 17 58 0b 07 06 8e 69 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}