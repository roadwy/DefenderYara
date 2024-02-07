
rule Trojan_BAT_AgentTesla_NM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 68 00 00 00 1e 00 00 00 5e 00 00 00 7f 01 00 00 4c 00 00 00 ae 00 00 00 ce 00 00 00 01 00 00 00 01 00 00 00 2c 00 00 00 0a 00 00 00 25 } //01 00 
		$a_01_1 = {50 69 7a 7a 61 5f 41 70 70 5f 55 73 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Pizza_App_User.Resources.resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NM_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 07 20 c3 06 fb 0d 58 0b 7b 90 01 03 04 6f 90 01 03 06 13 04 07 20 90 01 03 70 60 0b 08 6f 90 01 03 06 07 20 90 01 03 35 5e 0b 39 90 01 03 00 20 90 01 03 3a 07 43 90 01 03 00 02 11 04 6f 90 01 03 06 07 20 90 01 03 2f 61 0b 06 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {75 6e 6b 6e 6f 77 6e 73 70 66 5f 6c 6f 61 64 65 72 } //00 00  unknownspf_loader
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NM_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {02 8c 01 00 00 1b 2c 12 0f 00 fe 16 90 01 03 1b 6f 90 01 03 0a 2d 03 16 2b 01 17 00 13 04 11 04 39 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {56 00 45 00 35 00 4a 00 54 00 31 00 42 00 5a 00 55 00 6c 00 52 00 4f 00 52 00 51 00 3d 00 3d 00 } //01 00  VE5JT1BZUlRORQ==
		$a_01_2 = {5a 00 47 00 46 00 76 00 62 00 41 00 3d 00 3d 00 } //01 00  ZGFvbA==
		$a_01_3 = {43 00 6f 00 6d 00 70 00 6c 00 65 00 78 00 47 00 65 00 6e 00 } //01 00  ComplexGen
		$a_01_4 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 } //00 00  WinForms_SeeInnerException
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NM_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 45 5f 47 55 49 2e 52 65 73 6f 75 72 63 65 73 } //01 00  SE_GUI.Resources
		$a_81_1 = {53 45 5f 47 55 49 2e 41 64 6d 69 6e 50 61 67 65 2e 72 65 73 6f 75 72 63 65 73 } //01 00  SE_GUI.AdminPage.resources
		$a_81_2 = {67 65 74 5f 57 69 64 73 } //01 00  get_Wids
		$a_81_3 = {54 69 6d 65 72 32 5f 54 69 63 6b 5f 31 } //01 00  Timer2_Tick_1
		$a_81_4 = {52 65 71 75 65 73 74 42 74 6e 2e 49 63 6f 6e 69 6d 61 67 65 } //01 00  RequestBtn.Iconimage
		$a_81_5 = {73 65 72 76 65 72 3d 6c 6f 63 61 6c 68 6f 73 74 3b 75 73 65 72 20 69 64 3d 72 6f 6f 74 3b 64 61 74 61 62 61 73 65 3d 6d 61 6e 61 67 65 6d 65 6e 74 73 79 73 74 65 6d 3b } //01 00  server=localhost;user id=root;database=managementsystem;
		$a_81_6 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 } //00 00  System.Drawing.Bitmap
	condition:
		any of ($a_*)
 
}