
rule Trojan_Win32_AttackServerCloudBlockTest_A{
	meta:
		description = "Trojan:Win32/AttackServerCloudBlockTest.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 } //1 \powershell.exe 
		$a_00_1 = {30 00 34 00 62 00 65 00 35 00 38 00 62 00 34 00 2d 00 36 00 34 00 62 00 33 00 2d 00 34 00 37 00 64 00 34 00 2d 00 39 00 66 00 61 00 37 00 2d 00 64 00 31 00 35 00 65 00 65 00 31 00 37 00 32 00 35 00 61 00 34 00 39 00 } //1 04be58b4-64b3-47d4-9fa7-d15ee1725a49
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}