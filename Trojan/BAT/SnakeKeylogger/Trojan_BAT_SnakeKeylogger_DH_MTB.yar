
rule Trojan_BAT_SnakeKeylogger_DH_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 02 08 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 03 07 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b6 28 90 01 03 0a 13 04 06 11 04 6f 90 01 03 0a 26 07 03 6f 90 01 03 0a 17 da 33 04 90 00 } //10
		$a_81_1 = {47 5a 49 44 45 4b 4b 4b 4b } //1 GZIDEKKKK
		$a_81_2 = {58 4f 52 5f 44 65 63 72 79 70 74 } //1 XOR_Decrypt
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}