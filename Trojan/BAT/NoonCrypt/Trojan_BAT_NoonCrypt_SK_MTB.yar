
rule Trojan_BAT_NoonCrypt_SK_MTB{
	meta:
		description = "Trojan:BAT/NoonCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 06 72 ed 01 00 70 6f 30 00 00 0a 74 04 00 00 1b 28 02 00 00 06 72 fd 01 00 70 6f 30 00 00 0a 74 04 00 00 1b } //2
		$a_01_1 = {20 00 01 00 00 8d 39 00 00 01 80 cd 01 00 04 16 0b 38 4e 00 00 00 00 07 6a 0a 1e 0c 38 29 00 00 00 00 06 17 6a 5f 17 6a fe 01 0d 09 39 10 00 00 00 06 17 64 20 20 83 b8 ed 6e 61 0a 38 04 00 00 00 06 17 64 0a 00 08 17 59 0c 08 16 fe 02 13 04 11 04 3a ca ff ff } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}