
rule VirTool_Win32_Bofprochandle_A{
	meta:
		description = "VirTool:Win32/Bofprochandle.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 6f 66 73 74 6f 70 } //1 bofstop
		$a_01_1 = {61 6c 6c 6f 63 61 74 65 20 68 61 6e 64 6c 65 } //1 allocate handle
		$a_01_2 = {72 65 61 6c 6c 6f 63 61 74 65 20 68 61 6e 64 6c 65 } //1 reallocate handle
		$a_01_3 = {64 75 70 6c 69 63 61 74 65 20 68 61 6e 64 6c 65 } //1 duplicate handle
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 61 6c 6c 6f 63 61 74 65 20 6f 62 6a 65 63 74 4e 61 6d 65 49 6e 66 6f } //1 Failed to allocate objectNameInfo
		$a_01_5 = {6b 69 6c 6c 69 74 20 66 61 69 6c 65 64 } //1 killit failed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}