
rule Trojan_Win32_RokRat_YAC_MTB{
	meta:
		description = "Trojan:Win32/RokRat.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 8b c1 8b f2 30 18 40 83 ee 01 75 f8 5e 57 } //3
		$a_01_1 = {52 65 6c 65 61 73 65 5c 49 6e 6a 65 63 74 53 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } //1 Release\InjectShellcode.pdb
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}