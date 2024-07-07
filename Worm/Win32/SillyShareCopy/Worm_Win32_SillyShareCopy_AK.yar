
rule Worm_Win32_SillyShareCopy_AK{
	meta:
		description = "Worm:Win32/SillyShareCopy.AK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 41 73 73 69 67 6e 6d 65 6e 74 2e 65 78 65 } //1 \Assignment.exe
		$a_01_1 = {5c 6d 73 61 67 65 6e 74 2e 70 69 66 } //1 \msagent.pif
		$a_01_2 = {63 3a 00 64 3a 00 65 3a 00 66 3a 00 67 3a 00 68 3a 00 69 3a 00 6a 3a } //2
		$a_01_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=4
 
}