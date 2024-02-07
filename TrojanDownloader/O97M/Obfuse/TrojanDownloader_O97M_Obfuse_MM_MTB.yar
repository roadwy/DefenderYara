
rule TrojanDownloader_O97M_Obfuse_MM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 0c 2c 20 90 02 0c 2c 20 32 29 29 29 90 00 } //01 00 
		$a_01_1 = {28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 29 } //01 00  (UserForm1.Label1.Caption)
		$a_01_2 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 22 70 72 6f 63 65 73 73 22 29 2e 49 74 65 6d 28 22 70 61 72 61 6d 31 22 29 20 3d } //01 00  .Environment("process").Item("param1") =
		$a_01_3 = {2e 72 75 6e 20 22 63 6d 64 20 2f 63 20 63 61 6c 6c 20 25 70 61 72 61 6d 31 25 22 2c 20 32 } //01 00  .run "cmd /c call %param1%", 2
		$a_01_4 = {3d 20 22 32 31 32 33 32 66 32 39 37 61 35 37 61 35 61 37 34 33 38 39 34 61 30 65 34 61 38 30 31 66 63 33 22 } //00 00  = "21232f297a57a5a743894a0e4a801fc3"
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_MM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.MM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 } //01 00  = Environ$("USERPROFILE") &
		$a_03_1 = {28 22 53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 90 02 25 2c 20 31 29 90 00 } //01 00 
		$a_01_2 = {2e 43 6f 70 79 48 65 72 65 20 53 68 65 6c 6c 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 46 75 6c 6c 5f 66 49 4c 45 29 2e 49 74 65 6d 73 } //01 00  .CopyHere ShellApp.Namespace(Full_fILE).Items
		$a_01_3 = {2e 43 6f 70 79 48 65 72 65 20 53 68 65 6c 6c 41 70 70 7a 7a 2e 4e 61 6d 65 73 70 61 63 65 28 50 61 74 68 7a 7a 29 2e 49 74 65 6d 73 } //01 00  .CopyHere ShellAppzz.Namespace(Pathzz).Items
		$a_01_4 = {50 75 74 20 23 31 2c } //01 00  Put #1,
		$a_03_5 = {53 68 65 6c 6c 28 90 02 08 2c 20 31 29 90 00 } //01 00 
		$a_03_6 = {3d 20 53 70 6c 69 74 28 42 74 2c 20 22 90 02 01 22 29 90 00 } //01 00 
		$a_03_7 = {4f 70 65 6e 20 90 02 12 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 41 73 20 23 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}