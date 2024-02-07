
rule HackTool_Win32_Patcher_E{
	meta:
		description = "HackTool:Win32/Patcher.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8b 7d 0c eb 06 8a 06 aa 83 c6 02 66 83 3e 00 75 f4 c6 07 00 8b 45 0c } //01 00 
		$a_00_1 = {2e 73 6e 72 5f 6f 66 66 73 65 74 73 2e 6c 64 72 } //01 00  .snr_offsets.ldr
		$a_00_2 = {5c 72 65 67 70 61 74 63 68 2e 72 65 67 } //01 00  \regpatch.reg
		$a_00_3 = {57 61 74 65 72 6d 61 72 6b 20 50 61 74 63 68 65 72 } //01 00  Watermark Patcher
		$a_00_4 = {63 72 65 61 74 65 64 20 77 69 74 68 20 64 55 50 32 } //00 00  created with dUP2
	condition:
		any of ($a_*)
 
}