
rule Backdoor_Win32_Plugx_C{
	meta:
		description = "Backdoor:Win32/Plugx.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 00 00 00 00 78 62 69 6e 30 31 00 } //01 00 
		$a_03_1 = {53 33 c0 b1 90 01 01 8a 98 90 01 03 00 32 d9 88 98 90 01 03 00 40 3d 90 01 02 00 00 72 ea 90 00 } //01 00 
		$a_03_2 = {6a 40 68 00 10 00 00 68 90 01 02 00 00 6a 00 ff d3 8b f0 56 68 90 01 02 00 00 68 90 01 02 40 00 e8 67 fa ff ff 8b f8 6a 40 68 00 10 00 00 57 6a 00 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}