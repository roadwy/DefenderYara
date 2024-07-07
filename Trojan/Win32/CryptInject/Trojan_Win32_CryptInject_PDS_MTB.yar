
rule Trojan_Win32_CryptInject_PDS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {09 d8 69 c0 7b 0f 01 00 8a 0d 90 01 04 a3 90 09 05 00 a1 90 00 } //2
		$a_00_1 = {8b 45 ec 30 4a 04 03 c2 83 e0 03 0f b6 44 05 f4 30 42 05 81 fe e2 02 00 00 72 } //2
		$a_02_2 = {0f b6 c0 66 8b d0 66 c1 e2 04 66 2b d0 8b c6 f7 d8 66 c1 e2 02 66 2b c2 66 03 f8 8b 44 24 10 66 89 3d 90 09 07 00 66 8b 3d 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}