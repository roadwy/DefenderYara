
rule TrojanDropper_Win32_Sudiet_A{
	meta:
		description = "TrojanDropper:Win32/Sudiet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a c8 80 c1 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 72 ed b8 } //4
		$a_00_1 = {5c 00 54 00 44 00 4b 00 44 00 } //1 \TDKD
		$a_00_2 = {74 00 64 00 73 00 73 00 73 00 65 00 72 00 76 00 } //1 tdssserv
		$a_00_3 = {74 00 64 00 73 00 73 00 64 00 61 00 74 00 61 00 } //1 tdssdata
		$a_00_4 = {74 00 64 00 73 00 73 00 63 00 6d 00 64 00 } //1 tdsscmd
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}