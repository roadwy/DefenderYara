
rule HackTool_Win32_MicroKMS{
	meta:
		description = "HackTool:Win32/MicroKMS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {6d 69 63 72 6f 6b 6d 73 2e 74 78 74 } //microkms.txt  01 00 
		$a_80_1 = {77 77 77 2e 79 69 73 68 69 6d 65 69 2e 63 6e } //www.yishimei.cn  01 00 
		$a_80_2 = {4d 69 63 72 6f 4b 4d 53 } //MicroKMS  01 00 
		$a_80_3 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //DisableRealtimeMonitoring  01 00 
		$a_80_4 = {64 6c 2e 6c 6d 72 6a 78 7a 2e 63 6f 6d } //dl.lmrjxz.com  01 00 
		$a_80_5 = {6d 69 63 72 6f 6b 6d 73 2e 63 6f 6d } //microkms.com  00 00 
	condition:
		any of ($a_*)
 
}