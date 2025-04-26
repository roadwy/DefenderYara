
rule Backdoor_Win32_Ronged_gen_A{
	meta:
		description = "Backdoor:Win32/Ronged.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 54 24 1d 50 0f b6 44 24 20 51 52 50 8d 0c 2b 68 ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 20 } //1
		$a_01_1 = {6f 74 68 5f 64 6f 6d 61 69 6e 20 20 20 25 73 } //1 oth_domain   %s
		$a_01_2 = {4f 53 20 54 79 70 65 3a 20 20 20 20 20 57 6f 72 6b 73 74 61 74 69 6f 6e } //1 OS Type:     Workstation
		$a_01_3 = {48 4f 53 54 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 20 46 4f 52 20 5c 5c 25 73 } //1 HOST INFORMATION FOR \\%s
		$a_01_4 = {51 41 5a 32 77 73 78 33 65 64 63 00 00 00 00 53 41 4c 54 5c 77 65 62 75 73 65 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}