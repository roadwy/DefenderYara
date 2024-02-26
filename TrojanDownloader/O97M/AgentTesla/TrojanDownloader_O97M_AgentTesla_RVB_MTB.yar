
rule TrojanDownloader_O97M_AgentTesla_RVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 41 63 74 69 76 61 74 65 20 22 45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31 22 } //01 00  AppActivate "Error.TextBox1"
		$a_01_1 = {54 61 73 6b 49 44 20 3d 20 53 68 65 6c 6c 28 43 61 6c 63 2c 20 31 29 } //01 00  TaskID = Shell(Calc, 1)
		$a_03_2 = {43 61 6c 63 20 3d 20 5f 90 0c 02 00 45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31 90 00 } //01 00 
		$a_01_3 = {45 72 72 20 3c 3e 20 30 20 54 68 65 6e 20 4d 73 67 42 6f 78 20 22 43 61 6e 27 74 20 73 74 61 72 74 20 22 20 26 20 50 72 6f 67 72 61 6d } //01 00  Err <> 0 Then MsgBox "Can't start " & Program
		$a_01_4 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //00 00  Sub auto_open()
	condition:
		any of ($a_*)
 
}