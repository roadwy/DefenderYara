
rule Trojan_BAT_AgentTesla_HR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {71 75 69 63 6b 5f 73 63 72 65 65 6e 5f 72 65 63 6f 72 64 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  quick_screen_recorder.Properties.Resources
		$a_81_1 = {24 37 33 39 64 33 61 31 31 2d 31 66 37 34 2d 34 30 65 66 2d 38 63 61 38 2d 33 37 38 39 30 36 36 64 37 65 35 38 } //01 00  $739d3a11-1f74-40ef-8ca8-3789066d7e58
		$a_81_2 = {2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 4d 6f 64 75 6c 65 41 72 74 2f } //01 00  //github.com/ModuleArt/
		$a_81_3 = {2e 63 6f 6d 70 72 65 73 73 65 64 } //01 00  .compressed
		$a_81_4 = {63 6f 73 74 75 72 61 } //00 00  costura
	condition:
		any of ($a_*)
 
}