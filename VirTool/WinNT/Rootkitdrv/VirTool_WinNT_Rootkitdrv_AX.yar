
rule VirTool_WinNT_Rootkitdrv_AX{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.AX,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //01 00 
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 73 00 71 00 6c 00 6f 00 64 00 62 00 63 00 } //01 00 
		$a_01_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00 
		$a_01_3 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 15 00 20 40 00 8b 49 01 8b 02 c7 04 88 10 11 40 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //01 00 
		$a_01_4 = {b8 cd cc cc cc be 00 00 00 00 f7 65 04 8b da 89 74 24 5c c1 eb 04 0f 84 } //00 00 
	condition:
		any of ($a_*)
 
}