
rule Trojan_BAT_SnakeLogger_EXH_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.EXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 ?? ?? ?? ?? ?? 1f 10 ?? ?? ?? ?? ?? 9c 07 17 58 0b } //1
		$a_81_1 = {46 75 63 6b 4d 69 63 72 6f 73 6f 66 74 31 32 33 } //1 FuckMicrosoft123
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}