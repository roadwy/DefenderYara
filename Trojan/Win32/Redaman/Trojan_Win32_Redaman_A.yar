
rule Trojan_Win32_Redaman_A{
	meta:
		description = "Trojan:Win32/Redaman.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 72 69 74 65 50 72 6f 5f 5f 5f 5f 5f 65 5f 6f 72 79 } //1 pritePro_____e_ory
		$a_01_1 = {72 5f 61 5f 4c 69 62 72 61 72 79 41 } //1 r_a_LibraryA
		$a_03_2 = {85 d2 74 2d 31 c9 2b 0e f7 d9 83 ee 90 01 01 4e f7 d1 83 e9 90 01 01 01 d9 83 c1 90 01 01 49 89 cb 89 0f 83 c7 90 01 01 83 ea 90 01 01 8d 0d 90 01 04 81 c1 90 01 04 ff e1 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Redaman_A_2{
	meta:
		description = "Trojan:Win32/Redaman.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 rundll32.exe
		$a_00_1 = {63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 } //1 c:\programdata\
		$a_00_2 = {64 00 6c 00 6c 00 67 00 65 00 74 00 63 00 6c 00 61 00 73 00 73 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 68 00 6f 00 73 00 74 00 } //1 dllgetclassobject host
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}