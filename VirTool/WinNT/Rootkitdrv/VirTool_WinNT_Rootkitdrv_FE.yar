
rule VirTool_WinNT_Rootkitdrv_FE{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.FE,SIGNATURE_TYPE_PEHSTR_EXT,79 00 79 00 06 00 00 "
		
	strings :
		$a_02_0 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 a1 ?? ?? ?? ?? 50 68 } //100
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 57 00 69 00 6e 00 48 00 6f 00 6f 00 6b 00 } //10 \Device\WinHook
		$a_00_2 = {5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 79 00 64 00 64 00 6f 00 73 00 2e 00 65 00 78 00 65 00 } //10 \WINDOWS\system32\fyddos.exe
		$a_00_3 = {5c 69 33 38 36 5c 53 59 53 2e 70 64 62 } //1 \i386\SYS.pdb
		$a_00_4 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
		$a_00_5 = {57 69 6e 48 6f 6f 6b 3a 53 79 73 74 65 6d 43 61 6c 6c 53 65 72 76 69 63 65 3a 20 25 78 } //1 WinHook:SystemCallService: %x
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=121
 
}