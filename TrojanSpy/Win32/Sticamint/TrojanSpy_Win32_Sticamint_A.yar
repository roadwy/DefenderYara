
rule TrojanSpy_Win32_Sticamint_A{
	meta:
		description = "TrojanSpy:Win32/Sticamint.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {77 00 2e 00 77 00 64 00 77 00 90 02 16 67 00 2e 00 6e 00 65 00 74 00 2f 00 6e 00 65 00 74 00 90 00 } //01 00 
		$a_02_1 = {77 00 2e 00 31 00 37 00 35 00 75 00 90 02 16 75 00 2e 00 63 00 6e 00 2f 00 6e 00 65 00 74 00 90 00 } //02 00 
		$a_00_2 = {2f 00 64 00 6c 00 6c 00 2e 00 61 00 73 00 70 00 78 00 3f 00 74 00 69 00 6d 00 65 00 3d 00 } //02 00  /dll.aspx?time=
		$a_00_3 = {26 00 49 00 4e 00 54 00 3d 00 } //02 00  &INT=
		$a_00_4 = {2f 00 73 00 74 00 61 00 74 00 2e 00 61 00 73 00 70 00 78 00 } //00 00  /stat.aspx
	condition:
		any of ($a_*)
 
}