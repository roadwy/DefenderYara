
rule Ransom_Win32_ContiCrypt_MFP_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 88 4c 05 } //5
		$a_02_1 = {88 5d c7 c6 45 c8 90 01 01 c6 45 c9 90 01 01 c6 45 ca 90 01 01 c6 45 cb 90 01 01 c6 45 cc 90 01 05 c6 45 ce 90 01 01 c6 45 cf 90 01 01 c6 45 d0 90 01 01 c6 45 d1 90 01 01 c6 45 d2 90 01 01 c6 45 d3 90 01 01 c6 45 d4 90 01 01 48 89 45 6f 0f b6 45 c8 0f b6 45 c7 90 00 } //5
		$a_00_2 = {c6 45 88 67 c6 45 89 33 c6 45 8a 5f c6 45 8b 2d c6 45 8c 6c c6 45 8d 5f c6 45 8e 2b c6 45 8f 6e c6 45 90 57 c6 45 91 57 c6 45 92 50 0f b6 4d 88 48 89 45 67 0f b6 45 87 } //5
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*5) >=5
 
}