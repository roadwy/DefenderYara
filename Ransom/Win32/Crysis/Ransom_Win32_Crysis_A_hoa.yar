
rule Ransom_Win32_Crysis_A_hoa{
	meta:
		description = "Ransom:Win32/Crysis.A!hoa,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 63 72 79 73 69 73 5c 52 65 6c 65 61 73 65 5c 50 44 42 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //1 \crysis\Release\PDB\payload.pdb
		$a_02_1 = {8b 4d 0c 03 4d 90 01 01 0f b6 11 0f b6 45 90 01 01 0f b6 4d 90 01 01 03 c1 0f b6 c0 8b 4d 90 01 01 0f b6 04 01 33 d0 8b 4d 90 01 01 03 4d 90 01 01 88 11 e9 90 00 } //1
		$a_02_2 = {8b 45 0c 03 45 90 01 01 0f b6 08 0f b6 55 90 01 01 0f b6 45 90 01 01 03 d0 0f b6 d2 8b 45 90 01 01 0f b6 14 10 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 85 d2 75 90 01 01 8b 45 90 01 01 83 c0 90 01 01 89 45 90 01 01 eb 90 01 01 c7 45 90 01 05 e9 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}