
rule Trojan_Win32_VBKrypt_BI_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b 34 0a 0f 67 c1 90 02 5f 81 f6 90 01 04 0f 69 e5 90 02 ff 89 34 08 0f 63 d8 90 02 4f 49 90 02 ff 49 90 02 ff 49 90 02 ff 49 0f 8d 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}