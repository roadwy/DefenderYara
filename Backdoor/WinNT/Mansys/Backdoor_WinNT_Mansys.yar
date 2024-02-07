
rule Backdoor_WinNT_Mansys{
	meta:
		description = "Backdoor:WinNT/Mansys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 68 80 00 00 00 6a 02 56 6a 02 68 00 00 00 40 ff 75 90 01 01 ff 15 90 00 } //01 00 
		$a_02_1 = {66 81 e3 00 f0 66 81 fb 00 30 75 1e 90 02 15 75 90 01 01 66 90 02 06 c7 05 74 15 90 00 } //01 00 
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_3 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  NtQuerySystemInformation
		$a_00_4 = {5c 5c 2e 5c 68 74 74 70 73 } //00 00  \\.\https
	condition:
		any of ($a_*)
 
}