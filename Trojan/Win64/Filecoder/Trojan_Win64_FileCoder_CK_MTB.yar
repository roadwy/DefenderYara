
rule Trojan_Win64_FileCoder_CK_MTB{
	meta:
		description = "Trojan:Win64/FileCoder.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 0f b6 00 89 c1 8b 85 dc 20 00 00 99 f7 bd b8 20 00 00 89 d0 48 98 48 8d 15 f1 9b 00 00 0f b6 04 10 31 c8 89 c1 } //1
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 43 6c 61 73 73 } //1 RansomwareClass
		$a_01_2 = {2e 6c 6f 63 6b 65 64 } //1 .locked
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}