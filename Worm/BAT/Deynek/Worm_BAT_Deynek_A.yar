
rule Worm_BAT_Deynek_A{
	meta:
		description = "Worm:BAT/Deynek.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 79 64 65 6e 5c 53 74 75 62 5c 53 74 75 62 5c 6f 62 6a 5c } //01 00  keyden\Stub\Stub\obj\
		$a_01_1 = {2f 00 67 00 61 00 74 00 65 00 2e 00 70 00 68 00 70 00 3f 00 26 00 75 00 73 00 65 00 72 00 3d 00 } //01 00  /gate.php?&user=
		$a_01_2 = {61 00 6e 00 74 00 69 00 73 00 20 00 6f 00 66 00 66 00 } //01 00  antis off
		$a_01_3 = {66 00 69 00 6c 00 65 00 74 00 6f 00 73 00 70 00 72 00 65 00 61 00 64 00 } //01 00  filetospread
		$a_01_4 = {61 00 76 00 67 00 65 00 6d 00 63 00 } //01 00  avgemc
		$a_01_5 = {6d 00 63 00 61 00 67 00 65 00 6e 00 74 00 6d 00 63 00 75 00 69 00 6d 00 67 00 72 00 } //00 00  mcagentmcuimgr
	condition:
		any of ($a_*)
 
}