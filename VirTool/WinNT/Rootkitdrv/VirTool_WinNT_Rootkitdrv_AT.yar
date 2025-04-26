
rule VirTool_WinNT_Rootkitdrv_AT{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AT,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 53 00 61 00 66 00 65 00 4e 00 54 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 } //10 \Device\SafeNTKernel
		$a_00_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6e 00 74 00 6b 00 72 00 6e 00 6c 00 70 00 61 00 2e 00 65 00 78 00 65 00 } //10 \SystemRoot\System32\ntkrnlpa.exe
		$a_00_2 = {5c 64 72 69 76 65 72 5c 62 79 70 61 73 73 5c 62 79 70 61 73 73 5c 69 33 38 36 5c 62 79 70 61 73 73 2e 70 64 62 } //10 \driver\bypass\bypass\i386\bypass.pdb
		$a_00_3 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_02_4 = {68 6e 45 54 74 8b 45 ?? c1 e0 02 50 6a 00 ff 15 } //1
		$a_02_5 = {fa 0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 00 8b 15 } //1
		$a_02_6 = {fa 0f 20 c0 89 45 ?? 25 ff ff fe ff 0f 22 c0 a1 ?? ?? ?? ?? 8b 40 01 a3 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=33
 
}