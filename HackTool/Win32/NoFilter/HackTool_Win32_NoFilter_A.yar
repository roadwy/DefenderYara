
rule HackTool_Win32_NoFilter_A{
	meta:
		description = "HackTool:Win32/NoFilter.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {5c 44 65 62 75 67 5c 4e 6f 46 69 6c 74 65 72 2e 70 64 62 } //\Debug\NoFilter.pdb  1
		$a_80_1 = {66 77 70 75 63 6c 6e 74 2e 64 6c 6c } //fwpuclnt.dll  1
		$a_03_2 = {48 83 ec 28 48 8d 05 ?? ?? ?? ?? 48 83 c0 08 4c 8b c8 4c 8d 05 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? b9 06 00 00 00 e8 d6 05 00 00 48 83 c4 28 c3 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}