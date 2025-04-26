
rule VirTool_WinNT_Rootkitdrv_LP{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 6e 00 74 00 6f 00 73 00 6b 00 72 00 6e 00 6c 00 2e 00 65 00 78 00 65 00 } //1 \SystemRoot\SYSTEM32\ntoskrnl.exe
		$a_03_1 = {8b 0a ff 71 0c ff 71 08 ff 71 04 52 50 e8 ?? ?? ff ff 8b f8 33 c0 85 db 74 0a 0f b6 03 3d b8 00 00 00 74 ?? 85 f6 75 } //1
		$a_03_2 = {33 c0 f3 a6 74 05 1b c0 83 d8 ff 85 c0 75 0a c7 85 ?? ?? ff ff 01 00 00 00 83 bd ?? ?? ff ff 00 74 10 83 bd ?? ?? ff ff 01 74 07 b8 22 00 00 c0 eb ?? ff 75 1c ff 75 18 ff b5 ?? ?? ff ff ?? ff 75 0c ff b5 ?? ?? ff ff ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}