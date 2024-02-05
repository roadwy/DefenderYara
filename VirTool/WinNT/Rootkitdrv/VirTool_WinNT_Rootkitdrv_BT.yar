
rule VirTool_WinNT_Rootkitdrv_BT{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.BT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {56 8d 77 04 56 ff d3 84 c0 74 32 b1 1f ff 15 90 01 04 8a c8 0f 20 c0 25 ff ff fe ff 0f 22 c0 c7 07 90 01 02 00 00 c7 06 90 01 04 0f 20 c0 0d 00 00 01 00 0f 22 c0 90 00 } //01 00 
		$a_00_1 = {eb 03 0f be c0 88 04 0a 41 4e 75 e4 80 7d 08 2e 5e 75 16 80 7d 09 73 75 10 80 7d 0a 79 75 0a 80 7d 0b 73 75 04 b0 01 eb 02 } //00 00 
	condition:
		any of ($a_*)
 
}