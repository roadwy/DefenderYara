
rule TrojanProxy_Win32_Wopla_AG{
	meta:
		description = "TrojanProxy:Win32/Wopla.AG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 70 00 6f 00 6f 00 66 00 70 00 6f 00 6f 00 66 00 } //1 \device\poofpoof
		$a_00_1 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 6b 00 70 00 72 00 6f 00 66 00 } //1 \driver\kprof
		$a_01_2 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //1 ZwQueryInformationFile
		$a_00_3 = {7a 77 71 75 65 72 79 73 79 73 74 65 6d 69 6e 66 6f 72 6d 61 74 69 6f 6e } //1 zwquerysysteminformation
		$a_02_4 = {8d 7d c0 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 33 f6 3b c6 89 45 08 7d 17 3d 01 00 00 c0 74 07 3d 25 02 00 c0 75 09 83 c7 04 8b 07 3b c6 75 d5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}