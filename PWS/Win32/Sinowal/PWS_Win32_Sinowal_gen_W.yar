
rule PWS_Win32_Sinowal_gen_W{
	meta:
		description = "PWS:Win32/Sinowal.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 75 f8 5a ff 72 3c 58 8b 4d f8 0f b7 14 01 89 55 bc 8b 45 bc 25 ff 00 00 00 } //01 00 
		$a_01_1 = {8b 45 ec 6b c0 28 8b 4d f0 8b 54 08 08 83 ea 02 52 ff 75 ec } //01 00 
		$a_01_2 = {8b 55 08 8b 42 10 ff d0 85 c0 75 } //01 00 
		$a_00_3 = {3b f7 75 05 be 4f e6 40 bb } //01 00 
		$a_00_4 = {4e 76 43 70 6c 44 61 65 6d 6f 6e 54 6f 6f 6c } //00 00  NvCplDaemonTool
	condition:
		any of ($a_*)
 
}