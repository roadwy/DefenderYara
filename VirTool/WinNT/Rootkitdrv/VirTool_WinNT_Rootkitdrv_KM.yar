
rule VirTool_WinNT_Rootkitdrv_KM{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 57 00 69 00 6e 00 48 00 6f 00 6f 00 6b 00 } //1 \Device\WinHook
		$a_01_2 = {2a 57 69 6e 48 6f 6f 6b 3a 48 6f 6f 6b 20 53 79 73 74 65 6d 20 43 61 6c 6c 20 53 65 72 76 69 63 65 2a } //1 *WinHook:Hook System Call Service*
		$a_01_3 = {50 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}