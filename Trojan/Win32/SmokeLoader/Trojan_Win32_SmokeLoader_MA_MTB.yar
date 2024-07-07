
rule Trojan_Win32_SmokeLoader_MA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 8b d0 c1 ea 05 03 54 24 30 8b c8 c1 e1 04 89 54 24 1c 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d 68 73 7b 00 8b 44 24 1c 01 05 68 73 7b 00 } //5
		$a_01_1 = {8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c 89 4c 24 1c 8b 44 24 1c 29 44 24 14 8b 4c 24 14 8b c1 c1 e0 04 03 c3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_SmokeLoader_MA_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f4 8b c7 c1 e0 04 03 45 e0 89 45 f8 8b 45 f4 03 45 f0 89 45 0c ff 75 0c 83 0d 90 01 04 ff 8b d7 8d 45 f8 c1 ea 05 03 55 e8 50 c7 05 90 00 } //5
		$a_03_1 = {6a 73 58 6a 6d 66 a3 90 01 04 58 6a 67 66 a3 90 01 04 58 6a 69 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 32 66 a3 90 01 04 58 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}