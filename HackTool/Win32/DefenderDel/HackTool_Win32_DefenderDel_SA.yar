
rule HackTool_Win32_DefenderDel_SA{
	meta:
		description = "HackTool:Win32/DefenderDel.SA,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0f 00 00 0a 00 "
		
	strings :
		$a_80_0 = {72 65 6d 6f 76 65 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 } //remove windows defender  0a 00 
		$a_80_1 = {61 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 6c 65 74 65 20 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 } //are you sure you want to delete windows defender  0a 00 
		$a_80_2 = {64 65 66 65 6e 64 65 72 20 72 65 6d 6f 76 65 72 20 77 69 6c 6c } //defender remover will  0a 00 
		$a_80_3 = {70 32 63 73 65 72 76 } //p2cserv  01 00 
		$a_80_4 = {64 69 73 61 62 6c 65 72 65 61 6c 74 69 6d 65 6d 6f 6e 69 74 6f 72 69 6e 67 } //disablerealtimemonitoring  01 00 
		$a_80_5 = {64 69 73 61 62 6c 65 61 6e 74 69 76 69 72 75 73 } //disableantivirus  01 00 
		$a_80_6 = {64 69 73 61 62 6c 65 61 6e 74 69 73 70 79 77 61 72 65 } //disableantispyware  01 00 
		$a_80_7 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 20 28 78 38 36 29 5c 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 61 64 76 61 6e 63 65 64 20 74 68 72 65 61 74 20 70 72 6f 74 65 63 74 69 6f 6e } //program files (x86)\windows defender advanced threat protection  01 00 
		$a_80_8 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 61 64 76 61 6e 63 65 64 20 74 68 72 65 61 74 20 70 72 6f 74 65 63 74 69 6f 6e } //program files\windows defender advanced threat protection  01 00 
		$a_80_9 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 61 64 76 61 6e 63 65 64 20 74 68 72 65 61 74 20 70 72 6f 74 65 63 74 69 6f 6e } //programdata\microsoft\windows defender advanced threat protection  01 00 
		$a_80_10 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 6d 69 63 72 6f 73 6f 66 74 5c 73 74 6f 72 61 67 65 20 68 65 61 6c 74 68 } //programdata\microsoft\storage health  01 00 
		$a_80_11 = {77 64 62 6f 6f 74 2e 73 79 73 } //wdboot.sys  01 00 
		$a_80_12 = {77 64 64 65 76 66 6c 74 2e 73 79 73 } //wddevflt.sys  01 00 
		$a_80_13 = {77 64 66 69 6c 74 65 72 2e 73 79 73 } //wdfilter.sys  01 00 
		$a_80_14 = {77 64 6e 69 73 64 72 76 2e 73 79 73 } //wdnisdrv.sys  00 00 
	condition:
		any of ($a_*)
 
}