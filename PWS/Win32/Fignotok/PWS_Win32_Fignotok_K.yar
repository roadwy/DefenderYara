
rule PWS_Win32_Fignotok_K{
	meta:
		description = "PWS:Win32/Fignotok.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 74 09 c7 45 fc 00 00 00 00 eb 07 } //1
		$a_01_1 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07 } //1
		$a_03_2 = {58 59 59 59 6a 04 90 09 03 00 c7 45 } //1
		$a_01_3 = {8b f0 8d 78 01 c1 e6 02 31 7d f4 89 84 35 f4 fb ff ff 99 f7 7d f8 8b 45 10 0f be 04 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}