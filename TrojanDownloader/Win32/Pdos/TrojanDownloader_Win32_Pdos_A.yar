
rule TrojanDownloader_Win32_Pdos_A{
	meta:
		description = "TrojanDownloader:Win32/Pdos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 64 6f 73 2e 70 00 } //1
		$a_03_1 = {f3 ab 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 85 c0 55 16 8b f4 6a 05 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 2b f4 e8 } //1
		$a_00_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 } //1
		$a_00_3 = {57 69 6e 45 78 65 63 00 } //1 楗䕮數c
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}