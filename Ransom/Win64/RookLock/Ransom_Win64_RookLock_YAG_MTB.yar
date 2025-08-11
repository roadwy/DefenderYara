
rule Ransom_Win64_RookLock_YAG_MTB{
	meta:
		description = "Ransom:Win64/RookLock.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 72 75 35 65 69 72 6e 41 77 6f 6a 5a 76 46 4f 77 75 47 66 58 78 6c 2b 4f 71 6c 59 33 53 67 59 63 4c 58 38 38 4e 75 35 74 52 56 77 79 58 61 46 53 39 79 6d 2b 2b 69 54 42 79 61 54 70 78 64 2b } //5 Wru5eirnAwojZvFOwuGfXxl+OqlY3SgYcLX88Nu5tRVwyXaFS9ym++iTByaTpxd+
		$a_01_1 = {69 4b 67 6b 79 6b 47 46 30 30 48 4b 48 72 62 69 55 30 33 39 68 4a 35 42 66 53 46 6c 69 62 69 57 6b 56 62 43 4c 75 63 } //5 iKgkykGF00HKHrbiU039hJ5BfSFlibiWkVbCLuc
		$a_01_2 = {2e 00 6c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 .locked
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}