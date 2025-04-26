
rule VirTool_Win32_Wraith_A{
	meta:
		description = "VirTool:Win32/Wraith.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {67 69 74 6c 6b 65 72 6e 65 6c 68 6f 6f 6b 2e 73 79 73 } //1 gitlkernelhook.sys
		$a_81_1 = {5c 44 65 76 69 63 65 5c 67 68 6f 73 74 69 6e 74 68 65 6c 6f 67 73 } //1 \Device\ghostinthelogs
		$a_81_2 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 67 68 6f 73 74 69 6e 74 68 65 6c 6f 67 73 } //1 \DosDevices\ghostinthelogs
		$a_81_3 = {5c 44 72 69 76 65 72 5c 67 68 6f 73 74 69 6e 74 68 65 6c 6f 67 73 } //1 \Driver\ghostinthelogs
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}