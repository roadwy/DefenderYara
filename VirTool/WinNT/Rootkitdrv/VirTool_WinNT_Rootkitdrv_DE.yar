
rule VirTool_WinNT_Rootkitdrv_DE{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.DE,SIGNATURE_TYPE_PEHSTR_EXT,ffffff85 00 ffffff85 00 08 00 00 "
		
	strings :
		$a_02_0 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 60 8b 90 01 04 00 66 b8 e9 00 66 89 07 90 00 } //100
		$a_00_1 = {48 00 6f 00 6f 00 6b 00 53 00 79 00 73 00 } //10 HookSys
		$a_00_2 = {6e 00 74 00 6b 00 72 00 6e 00 6c 00 70 00 61 00 2e 00 65 00 78 00 65 00 } //10 ntkrnlpa.exe
		$a_00_3 = {5c 77 69 6e 64 64 6b 5c 73 72 63 5c 68 6f 6f 6b 69 6e 74 } //10 \winddk\src\hookint
		$a_00_4 = {47 61 6d 65 4d 6f 6e } //2 GameMon
		$a_00_5 = {5a 57 53 48 55 54 44 4f 57 4e 53 59 53 54 45 4d } //1 ZWSHUTDOWNSYSTEM
		$a_00_6 = {4e 74 41 63 63 65 70 74 43 6f 6e 6e 65 63 74 50 6f 72 74 } //1 NtAcceptConnectPort
		$a_00_7 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=133
 
}