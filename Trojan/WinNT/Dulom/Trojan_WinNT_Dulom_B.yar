
rule Trojan_WinNT_Dulom_B{
	meta:
		description = "Trojan:WinNT/Dulom.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 78 70 5f 78 38 36 5c 69 33 38 36 5c 65 6e 74 72 79 2e 70 64 62 } //1 wxp_x86\i386\entry.pdb
		$a_01_1 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 00 } //1
		$a_01_2 = {47 00 62 00 70 00 4b 00 6d 00 } //1 GbpKm
		$a_01_3 = {47 00 62 00 70 00 53 00 76 00 } //1 GbpSv
		$a_03_4 = {89 45 e0 c7 45 e4 ?? ?? ?? ?? c7 45 b4 ?? ?? ?? ?? 6a 1e 8d 4d b8 51 6a 01 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 01 ff 15 ?? ?? ?? ?? 89 45 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}