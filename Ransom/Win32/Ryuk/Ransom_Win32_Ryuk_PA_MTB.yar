
rule Ransom_Win32_Ryuk_PA_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f7 8b 45 ?? 0f b6 04 08 02 c3 8b f2 8a 14 0e 88 04 0e 8b 45 ?? 02 d3 88 14 08 0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 f7 8b 7d ?? 47 89 7d ?? 03 55 ?? 0f b6 04 0a 8b 55 ?? 02 c3 32 44 3a ?? 83 6d 0c 01 88 47 ?? 75 } //3
		$a_03_1 = {5c 73 68 65 6c 6c 5c 6c 65 67 61 63 79 73 61 6d 70 6c 65 73 5c 61 70 70 62 61 72 5c [0-10] 5c 41 70 70 42 61 72 2e 70 64 62 } //1
		$a_81_2 = {79 75 41 41 51 45 52 57 45 41 52 44 46 47 53 46 64 67 74 67 66 67 53 5a 58 41 57 51 46 41 73 } //1 yuAAQERWEARDFGSFdgtgfgSZXAWQFAs
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}