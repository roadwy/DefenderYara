
rule Ransom_Win32_Crysis_A_hoa{
	meta:
		description = "Ransom:Win32/Crysis.A!hoa,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 63 72 79 73 69 73 5c 52 65 6c 65 61 73 65 5c 50 44 42 5c 70 61 79 6c 6f 61 64 2e 70 64 62 } //1 \crysis\Release\PDB\payload.pdb
		$a_02_1 = {8b 4d 0c 03 4d ?? 0f b6 11 0f b6 45 ?? 0f b6 4d ?? 03 c1 0f b6 c0 8b 4d ?? 0f b6 04 01 33 d0 8b 4d ?? 03 4d ?? 88 11 e9 } //1
		$a_02_2 = {8b 45 0c 03 45 ?? 0f b6 08 0f b6 55 ?? 0f b6 45 ?? 03 d0 0f b6 d2 8b 45 ?? 0f b6 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 8b 4d ?? 03 4d ?? 0f b6 11 85 d2 75 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? eb ?? c7 45 ?? ?? ?? ?? ?? e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}