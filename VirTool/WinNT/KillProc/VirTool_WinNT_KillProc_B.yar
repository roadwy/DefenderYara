
rule VirTool_WinNT_KillProc_B{
	meta:
		description = "VirTool:WinNT/KillProc.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 45 00 53 00 53 00 44 00 54 00 44 00 4f 00 53 00 } //1 \RESSDTDOS
		$a_00_1 = {62 75 66 3a 20 6b 69 6c 6c 00 } //1 畢㩦欠汩l
		$a_01_2 = {61 64 72 65 73 73 20 69 73 3a 25 78 00 } //1
		$a_01_3 = {5a 77 54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 ZwTerminateProcess
		$a_03_4 = {8d 45 08 50 ff 75 08 ff 15 90 01 04 85 c0 7c 90 02 02 8d 45 e8 50 ff 75 08 ff 15 90 02 1a 6a 90 03 01 01 00 02 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}