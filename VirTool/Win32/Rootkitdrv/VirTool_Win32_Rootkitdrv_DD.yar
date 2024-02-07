
rule VirTool_Win32_Rootkitdrv_DD{
	meta:
		description = "VirTool:Win32/Rootkitdrv.DD,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 00 25 00 53 00 00 00 63 00 73 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 00 00 4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 } //02 00 
		$a_01_1 = {8a d0 0f 20 c0 89 44 24 08 0f ba f0 10 0f 22 c0 8b 44 24 10 8b 4c 24 18 49 8b 74 24 14 8b 38 f3 a5 8b 4c 24 20 49 8b 74 24 1c 8b 78 10 f3 a5 } //01 00 
		$a_01_2 = {4b 65 52 61 69 73 65 49 72 71 6c 54 6f 44 70 63 4c 65 76 65 6c } //01 00  KeRaiseIrqlToDpcLevel
		$a_01_3 = {4b 65 53 74 61 63 6b 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //00 00  KeStackAttachProcess
	condition:
		any of ($a_*)
 
}