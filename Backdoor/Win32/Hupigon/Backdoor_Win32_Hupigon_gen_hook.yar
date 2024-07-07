
rule Backdoor_Win32_Hupigon_gen_hook{
	meta:
		description = "Backdoor:Win32/Hupigon.gen!hook,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {fe ff 8b 55 fc 33 db 8a 5c 02 ff 83 eb 19 8d 45 f4 8b d3 e8 } //2
		$a_00_1 = {fe ff 85 c0 74 04 33 c0 eb 02 b0 01 f6 d8 1b c0 85 f6 74 04 85 c0 75 84 8b c6 5f 5e 5b 5d c2 08 00 8d 40 00 } //2
		$a_00_2 = {47 50 69 67 65 6f 6e 35 5f 53 68 61 72 65 64 } //2 GPigeon5_Shared
		$a_00_3 = {45 6e 75 6d 53 65 72 76 69 63 65 73 53 74 61 74 75 73 57 } //1 EnumServicesStatusW
		$a_00_4 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
		$a_01_5 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 NtQuerySystemInformation
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}