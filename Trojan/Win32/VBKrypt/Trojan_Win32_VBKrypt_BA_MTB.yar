
rule Trojan_Win32_VBKrypt_BA_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 49 0c 8b 1d 90 01 04 68 90 01 04 66 0f b6 04 01 66 2b 05 90 01 04 c7 85 90 01 01 ff ff ff 90 0a ff 00 3b 85 90 01 01 ff ff ff 0f 8f 90 01 02 00 00 90 00 } //1
		$a_02_1 = {8b 51 0c 88 04 3a 8b 0d 90 01 04 b8 01 00 00 00 03 c1 0f 80 90 01 04 a3 90 01 04 e9 90 01 02 ff ff 90 00 } //1
		$a_02_2 = {50 52 ff d7 50 a1 90 01 04 50 6a 00 ff 15 90 01 04 8d 4d c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}