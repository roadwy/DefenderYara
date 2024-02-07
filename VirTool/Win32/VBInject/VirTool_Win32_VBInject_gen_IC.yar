
rule VirTool_Win32_VBInject_gen_IC{
	meta:
		description = "VirTool:Win32/VBInject.gen!IC,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 50 00 69 00 45 00 6c 00 63 00 65 00 73 00 74 00 69 00 61 00 6c 00 2d 00 75 00 64 00 74 00 6f 00 6f 00 6c 00 73 00 2d 00 6e 00 65 00 74 00 2d 00 69 00 6e 00 64 00 65 00 74 00 65 00 63 00 74 00 61 00 62 00 6c 00 65 00 73 00 2e 00 76 00 62 00 70 00 } //01 00  @*\AC:\PiElcestial-udtools-net-indetectables.vbp
		$a_01_1 = {53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 } //00 00  SHDocVwCtl.WebBrowser
	condition:
		any of ($a_*)
 
}