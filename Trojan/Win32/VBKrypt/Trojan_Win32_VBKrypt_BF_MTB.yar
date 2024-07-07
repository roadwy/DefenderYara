
rule Trojan_Win32_VBKrypt_BF_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5a 00 6f 00 70 00 62 00 6f 00 78 00 2c 00 20 00 6e 00 63 00 } //1 Zopbox, nc
		$a_01_1 = {47 00 69 00 74 00 6f 00 69 00 6e 00 20 00 66 00 6f 00 65 00 63 00 74 00 } //1 Gitoin foect
		$a_01_2 = {42 00 6d 00 69 00 74 00 68 00 20 00 63 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Bmith coration
		$a_01_3 = {43 00 6c 00 65 00 72 00 6f 00 2e 00 65 00 78 00 65 00 } //1 Clero.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}