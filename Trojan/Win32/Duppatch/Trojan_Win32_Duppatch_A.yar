
rule Trojan_Win32_Duppatch_A{
	meta:
		description = "Trojan:Win32/Duppatch.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //1 DuplicateHandle
		$a_00_1 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
		$a_03_2 = {74 aa 8b 3d 90 01 02 40 00 8b 0f 83 c7 04 8b d3 51 52 8b 07 3b 05 90 01 02 40 00 0f 85 ce 00 00 00 e8 90 01 02 00 00 8b d0 33 c0 66 8b 47 06 6a 02 90 00 } //1
		$a_03_3 = {8b 7f 04 57 68 90 01 02 40 00 e8 90 01 02 00 00 83 f8 01 74 1d bf 90 01 02 40 00 b8 02 00 00 00 8b 7f 04 57 68 90 01 02 40 00 e8 90 01 02 00 00 83 f8 01 75 36 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}