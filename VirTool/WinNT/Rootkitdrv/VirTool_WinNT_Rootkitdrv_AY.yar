
rule VirTool_WinNT_Rootkitdrv_AY{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AY,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 52 00 6e 00 74 00 6d 00 32 00 } //10 \Device\Rntm2
		$a_00_1 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 72 00 75 00 6e 00 74 00 69 00 6d 00 65 00 32 00 } //10 \Registry\Machine\System\CurrentControlSet\Services\runtime2
		$a_02_2 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 c3 8b 44 24 04 25 00 f0 ff ff 66 81 38 4d 5a 75 ?? 8b 48 3c 81 3c 08 50 45 00 00 74 } //10
		$a_00_3 = {4b 65 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e 54 68 72 65 61 64 } //1 KeDelayExecutionThread
		$a_00_4 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_5 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 ZwQuerySystemInformation
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=32
 
}