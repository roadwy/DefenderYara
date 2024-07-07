
rule Trojan_Win32_VBKrypt_AK_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 34 0a 0f 6a f3 0f 63 cb 0f 6a d1 0f 6a cd 0f 67 d9 66 0f 6b fc 0f 6b cc 66 0f 68 f9 0f 67 e1 0f 6a d1 66 0f 6a da 66 0f 67 ed 66 0f 68 f4 0f 69 ed 5f } //1
		$a_02_1 = {66 0f 63 d2 81 f7 90 01 04 0f 6a fe 66 0f 67 eb 0f 6b f7 0f 6b d2 0f 6b c9 0f 68 c2 66 0f 6a d5 0f 63 d1 66 0f 68 ec 66 0f 6a f1 0f 6b f0 0f 6a d8 57 66 0f 67 d2 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}