
rule Trojan_Win32_RtPos_A_MTB{
	meta:
		description = "Trojan:Win32/RtPos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 72 6f 6a 65 63 74 73 5c 72 74 31 39 5c 52 65 6c 65 61 73 65 5c 72 74 31 39 2e 70 64 62 } //01 00  Projects\rt19\Release\rt19.pdb
		$a_01_1 = {76 00 6d 00 74 00 6f 00 6f 00 6c 00 73 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  vmtoolsd.exe
		$a_01_2 = {77 00 69 00 6e 00 64 00 62 00 67 00 2e 00 65 00 78 00 65 00 } //01 00  windbg.exe
		$a_01_3 = {6e 00 74 00 73 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  ntsd.exe
	condition:
		any of ($a_*)
 
}