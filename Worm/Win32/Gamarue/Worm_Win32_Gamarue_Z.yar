
rule Worm_Win32_Gamarue_Z{
	meta:
		description = "Worm:Win32/Gamarue.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {b8 6f 00 00 00 66 89 45 e8 b9 70 00 00 00 66 89 4d ea ba 65 00 00 00 66 89 55 ec b8 6e 00 00 00 66 89 45 ee 33 c9 66 89 4d f0 } //1
		$a_00_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 } //1
		$a_02_2 = {c7 45 fc 42 00 00 00 0f b6 90 02 05 83 90 01 01 4e 90 00 } //1
		$a_00_3 = {c6 45 c8 64 c6 45 c9 65 c6 45 ca 73 c6 45 cb 6b c6 45 cc 74 c6 45 cd 6f c6 45 ce 70 c6 45 cf 2e c6 45 d0 69 c6 45 d1 6e c6 45 d2 69 } //1
		$a_00_4 = {c6 45 bc 64 c6 45 bd 65 c6 45 be 73 c6 45 bf 6b c6 45 c0 74 c6 45 c1 6f c6 45 c2 70 c6 45 c3 2e c6 45 c4 69 c6 45 c5 6e c6 45 c6 69 } //1
		$a_00_5 = {c6 45 d4 64 c6 45 d5 65 c6 45 d6 73 c6 45 d7 6b c6 45 d8 74 c6 45 d9 6f c6 45 da 70 c6 45 db 2e c6 45 dc 69 c6 45 dd 6e c6 45 de 69 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=3
 
}