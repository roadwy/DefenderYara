
rule Backdoor_Win32_Pliori_A{
	meta:
		description = "Backdoor:Win32/Pliori.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f0 89 3e 8b d6 83 c2 05 8b c3 e8 90 01 03 00 8b d6 83 c2 04 88 02 c6 03 e9 47 8b 45 f4 90 00 } //1
		$a_01_1 = {0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5 } //1
		$a_03_2 = {b8 20 4e 00 00 e8 90 01 03 ff e8 90 01 03 ff 8d 45 fc e8 90 01 03 ff 8d 45 fc 50 8d 4d f8 66 ba d2 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}