
rule Trojan_Win32_Ursnif_DB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d0 2b d1 8b 0d ?? ?? ?? ?? 83 c1 63 03 ca 89 0d ?? ?? ?? ?? 81 c6 38 84 0b 01 0f b6 c8 89 35 ?? ?? ?? ?? 66 83 c1 63 89 b4 3b ?? ?? ?? ?? 83 c7 04 8b 1d ?? ?? ?? ?? 66 03 cb 0f b7 d1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 ce 90 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 c1 ca 08 e2 e6 } //3
		$a_81_1 = {63 3a 5c 73 6d 69 6c 65 5c 53 65 63 74 69 6f 6e 5c 41 72 65 5c 77 68 69 63 68 5c 62 6f 6f 6b 5c 73 61 6c 74 5c 72 61 6e 67 65 5c 53 75 62 6a 65 63 74 5c 6f 62 6a 65 63 74 68 69 67 68 2e 70 64 62 } //1 c:\smile\Section\Are\which\book\salt\range\Subject\objecthigh.pdb
		$a_81_2 = {6d 69 78 73 65 61 74 2e 65 78 65 } //1 mixseat.exe
		$a_81_3 = {70 72 6f 74 6f 63 6f 6c 5c 53 74 64 46 69 6c 65 45 64 69 74 69 6e 67 5c 73 65 72 76 65 72 } //1 protocol\StdFileEditing\server
	condition:
		((#a_01_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}