
rule Trojan_Win32_Shelm_RA_MTB{
	meta:
		description = "Trojan:Win32/Shelm.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 b0 18 40 00 10 59 40 3d dc 05 00 00 90 01 01 f1 90 00 } //01 00 
		$a_01_1 = {73 74 75 64 79 5c 73 68 65 6c 6c 63 6f 64 65 5f 64 6c 6c 5c 52 65 6c 65 61 73 65 5c 73 68 65 6c 6c 63 6f 64 65 5f 64 6c 6c 2e 70 64 62 } //01 00  study\shellcode_dll\Release\shellcode_dll.pdb
		$a_01_2 = {69 6e 6a 65 63 74 } //00 00  inject
	condition:
		any of ($a_*)
 
}