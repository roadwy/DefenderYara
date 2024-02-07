
rule VirTool_Win32_Shrine_A{
	meta:
		description = "VirTool:Win32/Shrine.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 63 61 6c 6c 2e 4c 61 7a 79 44 4c 4c } //01 00  syscall.LazyDLL
		$a_01_1 = {4c 61 7a 79 44 4c 4c 29 2e 4e 65 77 50 72 6f 63 } //01 00  LazyDLL).NewProc
		$a_01_2 = {62 72 69 6d 73 74 6f 6e 65 2f 67 6f 2d 73 68 65 6c 6c 63 6f 64 65 2e 52 75 6e } //01 00  brimstone/go-shellcode.Run
		$a_01_3 = {62 72 69 6d 73 74 6f 6e 65 2f 67 6f 2d 73 68 65 6c 6c 63 6f 64 65 2e 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  brimstone/go-shellcode.VirtualProtect
	condition:
		any of ($a_*)
 
}