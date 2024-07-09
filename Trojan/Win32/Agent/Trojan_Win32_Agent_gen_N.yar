
rule Trojan_Win32_Agent_gen_N{
	meta:
		description = "Trojan:Win32/Agent.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 06 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec 00 02 00 00 80 a5 00 ff ff ff 00 56 57 6a 3f 59 33 c0 8d bd 01 ff ff ff 80 a5 00 fe ff ff 00 f3 ab 66 ab aa 6a 3f 33 c0 59 8d bd 01 fe ff ff f3 ab 66 ab aa 8d 85 00 fe ff ff 68 04 01 00 00 50 ff 15 ?? ?? 40 00 8d 85 00 fe ff ff 68 ?? ?? 40 00 50 e8 64 03 00 00 8d 85 00 fe ff ff 50 e8 ?? ?? ?? ?? 83 c4 0c 84 c0 } //10
		$a_00_1 = {7e 74 69 00 2e 4c 6f 47 00 00 00 00 2e 64 6c 6c } //10
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 00 00 4b 61 76 00 72 65 67 65 64 69 74 20 2f 73 20 00 22 3d 22 22 00 00 00 00 22 00 00 00 5b 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 5d } //10
		$a_00_3 = {77 69 6e 73 79 73 2e 72 65 67 } //1 winsys.reg
		$a_00_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 74 6d 70 46 69 6c 65 } //1 C:\WINDOWS\SYSTEM32\tmpFile
		$a_00_5 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73 } //1 EnumProcesses
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=33
 
}