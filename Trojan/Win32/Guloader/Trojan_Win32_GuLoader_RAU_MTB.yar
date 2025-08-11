
rule Trojan_Win32_GuLoader_RAU_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {63 72 6f 6f 6b 6c 65 67 67 65 64 20 64 65 61 6e 20 70 75 72 72 65 72 } //1 crooklegged dean purrer
		$a_81_1 = {63 6f 73 70 68 65 72 65 64 20 6d 69 63 72 6f 74 65 6c 65 70 68 6f 6e 69 63 } //1 cosphered microtelephonic
		$a_81_2 = {63 6f 65 6d 62 65 64 64 65 64 20 73 6b 61 65 72 74 6f 72 73 64 61 67 20 61 72 62 65 6a 64 73 6d 69 6c 6a 6b 6f 6e 73 75 6c 65 6e 74 } //1 coembedded skaertorsdag arbejdsmiljkonsulent
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}