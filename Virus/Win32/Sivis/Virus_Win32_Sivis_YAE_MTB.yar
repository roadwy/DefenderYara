
rule Virus_Win32_Sivis_YAE_MTB{
	meta:
		description = "Virus:Win32/Sivis.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 2f 65 78 70 2f 00 76 69 73 75 61 00 2e 2e 00 20 5b 46 69 6c 65 5d 20 } //1
		$a_03_1 = {8b 4c b0 4c 8b 54 b0 08 57 8b 78 04 c1 c9 ?? 03 4c b8 4c c1 ca ?? 03 54 b8 08 89 4c b0 08 } //1
		$a_01_2 = {69 d2 fb b4 a9 53 29 c0 40 2b c2 89 41 44 69 c0 fb b4 a9 53 29 d2 42 2b d0 52 58 } //10
		$a_03_3 = {68 14 00 00 00 68 00 00 00 00 68 b8 56 40 00 e8 fc 0f 00 00 83 c4 ?? 68 00 00 00 00 e8 f5 0f 00 00 a3 bc 56 40 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10+(#a_03_3  & 1)*10) >=22
 
}