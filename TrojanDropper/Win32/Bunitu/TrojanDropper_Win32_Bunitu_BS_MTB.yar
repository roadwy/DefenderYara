
rule TrojanDropper_Win32_Bunitu_BS_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e9 03 89 0d 90 01 04 8b 15 90 01 04 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 03 05 90 01 04 a3 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //1
		$a_00_1 = {81 e9 09 b5 00 00 51 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Bunitu_BS_MTB_2{
	meta:
		description = "TrojanDropper:Win32/Bunitu.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e8 03 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 89 15 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //1
		$a_02_1 = {ba 06 00 00 00 85 d2 74 90 01 01 a1 90 01 04 3b 45 90 01 01 72 90 01 01 eb 90 01 01 8b 4d 90 01 01 03 0d 90 01 04 c6 01 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule TrojanDropper_Win32_Bunitu_BS_MTB_3{
	meta:
		description = "TrojanDropper:Win32/Bunitu.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 e8 03 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 89 15 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //1
		$a_02_1 = {6a 06 6a 06 e8 90 01 04 83 c4 08 e8 90 01 04 e8 90 01 04 83 2d 90 01 04 02 b8 69 00 00 00 8b 0d 90 01 04 66 89 01 ba 65 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}