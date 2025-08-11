
rule Trojan_BAT_SnakeLogger_ACH_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0f 00 28 ?? 00 00 0a 0b 0f 00 28 ?? 00 00 0a 0c 04 } //1
		$a_03_1 = {0a 06 0e 07 0e 08 28 ?? 00 00 06 0b 03 04 0e 06 28 ?? 00 00 06 0c 03 07 08 0e 06 0e 08 } //1
		$a_01_2 = {06 16 61 d2 0a 07 20 ff 00 00 00 5f d2 0b 08 16 60 d2 0c 04 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}