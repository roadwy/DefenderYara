
rule PWS_Win32_PillowMint_A{
	meta:
		description = "PWS:Win32/PillowMint.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_1 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_81_2 = {41 63 63 6f 75 6e 74 69 6e 67 49 51 2e 65 78 65 } //1 AccountingIQ.exe
		$a_00_3 = {c7 85 f0 02 00 00 00 00 00 00 8b 85 f0 02 00 00 48 98 48 3d 89 00 00 00 77 2d 8b 85 f0 02 00 00 48 98 0f b6 84 05 20 02 00 00 83 f0 70 89 c2 8b 85 f0 02 00 00 48 98 88 94 05 90 01 00 00 83 85 f0 02 00 00 01 eb c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}