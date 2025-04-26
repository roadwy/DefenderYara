
rule Worm_Win32_SillyShareCopy_F{
	meta:
		description = "Worm:Win32/SillyShareCopy.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_1 = {4b 41 56 33 32 2e 65 78 65 00 00 00 ff ff ff ff 09 00 00 00 4b 41 56 44 58 2e 65 78 65 00 } //2
		$a_01_2 = {41 75 74 6f 52 75 6e 2e 69 6e 66 00 ff ff ff ff 10 00 00 00 5b 41 75 74 6f 52 75 6e 5d 0d 0a } //2
		$a_01_3 = {64 6f 77 6e 75 72 6c 3d 68 74 74 70 3a } //1 downurl=http:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}