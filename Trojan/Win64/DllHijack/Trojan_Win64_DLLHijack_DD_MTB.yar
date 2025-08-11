
rule Trojan_Win64_DLLHijack_DD_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 70 63 6c 69 65 6e 74 2e 64 6c 6c } //5 mpclient.dll
		$a_81_1 = {43 3a 2f 50 72 6f 67 72 61 6d 44 61 74 61 2f 50 6f 77 65 72 54 6f 79 73 2f } //10 C:/ProgramData/PowerToys/
		$a_81_2 = {64 32 76 74 6b 74 31 31 62 31 61 37 7a 73 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 } //10 d2vtkt11b1a7zs.cloudfront.net
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10) >=25
 
}