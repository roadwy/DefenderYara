
rule VirTool_WinNT_Rootkitdrv_GD{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {68 00 56 00 00 68 ?? ?? ?? ?? 8d 45 ec 50 56 56 56 ff 75 fc ff 15 } //1
		$a_03_1 = {8b 40 01 8b 09 [0-08] 8b 34 81 80 3e e9 } //1
		$a_01_2 = {0f 20 c0 8b d8 81 e3 ff ff fe ff 0f 22 c3 } //1
		$a_00_3 = {53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 76 00 73 00 5f 00 6d 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //1 SystemRoot\System32\vs_mon.dll
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_5 = {4b 65 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //1 KeAttachProcess
		$a_00_6 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //1 ZwQueryInformationProcess
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}