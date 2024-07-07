
rule Trojan_Win32_VBKrypt_AF_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 fb 00 66 81 90 02 ff ff d2 90 02 ff ff 37 90 02 2f 5b 90 02 2f 31 f3 90 02 2f 01 1c 10 90 02 2f 83 c2 04 90 02 4f 81 fa 90 01 02 00 00 0f 85 90 01 01 ff ff ff 90 02 4f ff d0 90 00 } //1
		$a_02_1 = {8b 14 0a f7 c7 90 02 ff ff d2 90 02 ff ff 37 90 02 2f 5b 90 02 2f 31 f3 90 02 3f 8f 04 10 90 02 2f 83 c2 04 90 02 4f 81 fa 90 01 02 00 00 0f 85 90 01 02 ff ff 90 02 4f ff d0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}