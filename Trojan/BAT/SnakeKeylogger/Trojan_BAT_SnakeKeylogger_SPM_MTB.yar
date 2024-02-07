
rule Trojan_BAT_SnakeKeylogger_SPM_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 06 16 06 8e 69 6f 90 01 03 0a 00 28 90 01 03 0a 72 15 05 00 70 6f 90 01 03 0a 0b 02 07 16 07 8e 69 90 00 } //01 00 
		$a_01_1 = {4c 61 6b 6b 61 50 6c 61 79 6c 69 73 74 54 6f 6f 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  LakkaPlaylistTool.Properties.Resources
	condition:
		any of ($a_*)
 
}