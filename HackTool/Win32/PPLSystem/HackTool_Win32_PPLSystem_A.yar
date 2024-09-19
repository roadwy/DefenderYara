
rule HackTool_Win32_PPLSystem_A{
	meta:
		description = "HackTool:Win32/PPLSystem.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {6c 69 62 72 61 72 79 5c 63 6f 72 65 5c 73 72 63 5c 65 73 63 61 70 65 2e 72 73 } //library\core\src\escape.rs  1
		$a_80_1 = {73 79 73 5c 73 79 6e 63 5c 72 77 6c 6f 63 6b 5c 66 75 74 65 78 2e 72 73 } //sys\sync\rwlock\futex.rs  1
		$a_80_2 = {70 69 64 41 72 67 73 44 4c 4c 50 61 74 68 20 6f 66 20 74 68 65 20 28 75 6e 73 69 67 6e 65 64 29 20 44 4c 4c 20 74 6f 20 69 6e 6a 65 63 74 44 55 4d 50 57 68 65 72 65 20 74 6f 20 77 72 69 74 65 20 74 68 65 } //pidArgsDLLPath of the (unsigned) DLL to injectDUMPWhere to write the  1
		$a_80_3 = {6c 69 76 65 64 75 6d 70 20 6f 6e 20 64 69 73 6b 20 28 6d 75 73 74 20 62 65 20 61 20 66 75 6c 6c 20 70 61 74 68 29 50 49 44 54 61 72 67 65 74 20 50 49 44 20 74 6f 20 69 6e 6a 65 63 74 } //livedump on disk (must be a full path)PIDTarget PID to inject  1
		$a_80_4 = {52 65 6d 6f 74 65 20 43 4f 4d 20 73 65 63 72 65 74 } //Remote COM secret  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}