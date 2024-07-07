
rule Trojan_Win32_VBKrypt_AC_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {83 c4 04 ff 34 1f } //1
		$a_00_1 = {31 34 24 e9 } //1
		$a_00_2 = {83 c4 04 89 14 18 } //1
		$a_02_3 = {83 c4 04 83 fb 00 0f 85 90 01 02 ff ff e9 90 01 02 00 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}