
rule Trojan_BAT_Masslogger_SS_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 2e 46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FolderOrganiser.FolderOrganiserForm.resources
		$a_01_1 = {50 69 78 65 6c 5f 44 65 6e 73 69 74 79 2e 46 6f 72 6d 44 65 6e 73 69 74 79 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Pixel_Density.FormDensity.resources
		$a_01_2 = {50 69 78 65 6c 5f 44 65 6e 73 69 74 79 2e 46 6f 72 6d 49 6e 74 72 6f 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Pixel_Density.FormIntro.resources
		$a_01_3 = {46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 2e 49 6e 76 61 6c 69 64 50 61 74 68 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FolderOrganiser.InvalidPath.resources
		$a_01_4 = {63 68 65 63 6b 49 6e 74 65 72 6e 65 74 2e 4c 6f 67 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  checkInternet.LoginForm.resources
		$a_01_5 = {54 69 6d 65 72 2e 4d 61 69 6e 57 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Timer.MainWindow.resources
		$a_01_6 = {46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 2e 4e 6f 46 69 6c 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FolderOrganiser.NoFiles.resources
		$a_01_7 = {46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 2e 4e 6f 52 61 64 69 6f 42 75 74 74 6f 6e 53 65 6c 65 63 74 65 64 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FolderOrganiser.NoRadioButtonSelected.resources
		$a_01_8 = {54 69 6d 65 72 2e 4f 70 74 69 6f 6e 73 57 69 6e 64 6f 77 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Timer.OptionsWindow.resources
		$a_01_9 = {77 69 6e 66 6f 72 6d 5f 70 61 67 69 6e 61 74 69 6f 6e 2e 45 78 74 50 61 67 69 6e 61 74 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  winform_pagination.ExtPagination.resources
		$a_01_10 = {46 6f 6c 64 65 72 4f 72 67 61 6e 69 73 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  FolderOrganiser.Properties.Resources.resources
		$a_01_11 = {77 69 6e 66 6f 72 6d 5f 70 61 67 69 6e 61 74 69 6f 6e 2e 53 61 6d 70 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  winform_pagination.Sample.resources
		$a_01_12 = {67 65 74 5f 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 } //01 00  get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq
		$a_01_13 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 } //01 00  GetEnvironmentVariable
		$a_01_14 = {49 50 53 74 61 74 75 73 } //01 00  IPStatus
		$a_01_15 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_16 = {41 70 70 44 6f 6d 61 69 6e } //01 00  AppDomain
		$a_01_17 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_18 = {67 65 74 5f 53 65 6c 65 63 74 65 64 50 61 74 68 } //01 00  get_SelectedPath
		$a_01_19 = {42 6c 6f 63 6b 43 6f 70 79 } //00 00  BlockCopy
	condition:
		any of ($a_*)
 
}