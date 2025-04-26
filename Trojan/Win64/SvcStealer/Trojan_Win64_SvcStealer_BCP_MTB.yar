
rule Trojan_Win64_SvcStealer_BCP_MTB{
	meta:
		description = "Trojan:Win64/SvcStealer.BCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d d1 de a9 68 88 44 24 4a 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4b 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4c 69 c0 cf 1c 13 00 2d d1 de a9 68 88 44 24 4d } //2
		$a_81_1 = {2f 73 76 63 73 74 65 61 6c 65 72 2f 67 65 74 2e 70 68 70 } //1 /svcstealer/get.php
		$a_81_2 = {31 38 35 2e 38 31 2e 36 38 2e 31 35 } //1 185.81.68.15
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}