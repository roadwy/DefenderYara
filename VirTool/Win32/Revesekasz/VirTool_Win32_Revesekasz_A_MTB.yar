
rule VirTool_Win32_Revesekasz_A_MTB{
	meta:
		description = "VirTool:Win32/Revesekasz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 24 90 01 03 89 44 24 20 c7 44 24 1c 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 8b 45 0c 89 44 24 04 c7 04 24 00 00 00 00 a1 5c 81 40 00 90 01 02 83 ec 28 90 00 } //1
		$a_03_1 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 06 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 02 00 00 00 a1 24 82 40 00 90 01 02 83 ec 18 89 45 f0 83 7d f0 ff 90 00 } //1
		$a_03_2 = {89 45 e8 89 55 ec c7 45 f4 01 00 00 00 8b 45 e8 8b 55 ec 09 d0 85 c0 90 01 02 8b 45 e8 8b 55 ec 89 44 24 0c 89 54 24 10 8b 45 0c 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}