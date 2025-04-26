
rule TrojanDownloader_Win32_Karagany_N{
	meta:
		description = "TrojanDownloader:Win32/Karagany.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {c1 e1 02 03 f9 8b 77 0c 03 75 ?? 8a 0e 3a 4d ?? 75 ?? 8a 4e 03 3a 4d ?? 75 ?? 8a 4e 07 } //1
		$a_03_1 = {8a 0b 8b 75 ?? 88 0c 06 8d 48 01 8b 75 ?? 0f af 4e 04 8b 75 ?? 0f b6 34 ?? 33 ce 8b 75 ?? 88 0c 06 43 40 4a 75 } //1
		$a_02_2 = {89 45 f0 c6 45 ?? 43 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 74 c6 45 ?? 65 c6 45 ?? 54 c6 45 ?? 68 c6 45 ?? 72 c6 45 ?? 65 c6 45 ?? 61 c6 45 ?? 64 c6 45 ?? 00 8d 45 ?? 50 8b 45 ?? 50 ff 55 } //1
		$a_00_3 = {30 18 40 fe cb 84 db 75 02 b3 e5 e2 f3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}