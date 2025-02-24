
rule Ransom_Win64_Clop_AMCV_MTB{
	meta:
		description = "Ransom:Win64/Clop.AMCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 07 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 83 e0 7f 0f b6 0c 38 0f b6 44 14 ?? 32 c8 88 4c 14 ?? 48 ff c2 48 83 fa } //5
		$a_80_1 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin Delete Shadows /all /quiet  5
		$a_80_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 74 69 6d 65 6f 75 74 20 37 20 26 20 64 65 6c 20 22 25 73 22 } //cmd.exe /c timeout 7 & del "%s"  4
		$a_80_3 = {49 67 6e 6f 72 69 6e 67 20 66 69 6c 65 20 77 69 74 68 20 62 6c 6f 63 6b 6c 69 73 74 65 64 20 65 78 74 65 6e 73 69 6f 6e } //Ignoring file with blocklisted extension  2
		$a_80_4 = {49 67 6e 6f 72 69 6e 67 20 62 6c 6f 63 6b 6c 69 73 74 65 64 20 64 69 72 65 63 74 6f 72 79 } //Ignoring blocklisted directory  2
		$a_80_5 = {6e 65 74 20 73 74 6f 70 20 22 53 51 4c 73 61 66 65 20 46 69 6c 74 65 72 20 53 65 72 76 69 63 65 22 20 2f 79 } //net stop "SQLsafe Filter Service" /y  1
		$a_80_6 = {6e 65 74 20 73 74 6f 70 20 52 65 70 6f 72 74 53 65 72 76 65 72 20 2f 79 } //net stop ReportServer /y  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=20
 
}