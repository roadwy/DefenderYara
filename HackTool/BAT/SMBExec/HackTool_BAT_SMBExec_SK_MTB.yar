
rule HackTool_BAT_SMBExec_SK_MTB{
	meta:
		description = "HackTool:BAT/SMBExec.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 33 34 34 65 65 35 35 61 2d 34 65 33 32 2d 34 36 66 32 2d 61 30 30 33 2d 36 39 61 64 35 32 62 35 35 39 34 35 } //01 00  $344ee55a-4e32-46f2-a003-69ad52b55945
		$a_01_1 = {53 68 61 72 70 49 6e 76 6f 6b 65 2d 53 4d 42 45 78 65 63 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 4d 42 42 42 42 2e 70 64 62 } //01 00  SharpInvoke-SMBExec\obj\Release\SMBBBB.pdb
		$a_01_2 = {53 4d 42 42 42 42 2e 65 78 65 } //00 00  SMBBBB.exe
	condition:
		any of ($a_*)
 
}