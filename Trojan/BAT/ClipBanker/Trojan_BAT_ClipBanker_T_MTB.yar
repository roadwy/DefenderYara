
rule Trojan_BAT_ClipBanker_T_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 1f 0b 0b 07 06 58 0a 2a } //2 ਖଟ܋堆⨊
		$a_01_1 = {0a 16 0b 2b 11 06 07 93 0c 08 03 58 d1 0c 06 07 08 9d 07 17 58 0b 07 06 8e 69 32 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}