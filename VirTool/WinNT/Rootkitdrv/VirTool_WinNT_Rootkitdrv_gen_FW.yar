
rule VirTool_WinNT_Rootkitdrv_gen_FW{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {ff 35 04 09 01 00 ff 15 90 01 04 68 9a 02 00 00 8a d8 ff 15 90 01 04 0f b6 c3 50 68 90 01 04 8d 85 00 ff ff ff 68 fd 00 00 00 50 90 00 } //01 00 
		$a_00_1 = {52 4f 4f 54 4b 49 54 3a 20 4f 6e 55 6e 6c 6f 61 64 20 63 61 6c 6c 65 64 } //00 00  ROOTKIT: OnUnload called
	condition:
		any of ($a_*)
 
}