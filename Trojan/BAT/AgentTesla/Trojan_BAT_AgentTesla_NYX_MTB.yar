
rule Trojan_BAT_AgentTesla_NYX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 44 5f 4f 6c 79 6d 70 69 61 64 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } //01 00  BD_Olympiads.Properties.Resource
		$a_01_1 = {62 00 69 00 6e 00 64 00 69 00 6e 00 67 00 4e 00 61 00 76 00 69 00 67 00 61 00 74 00 6f 00 72 00 4d 00 6f 00 76 00 65 00 4e 00 65 00 78 00 74 00 49 00 74 00 65 00 6d 00 } //01 00  bindingNavigatorMoveNextItem
		$a_01_2 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  MD5CryptoServiceProvider
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {24 62 30 39 36 37 31 36 65 2d 65 64 30 66 2d 34 64 64 33 2d 39 30 63 65 2d 31 34 38 36 38 31 33 34 35 63 62 66 } //00 00  $b096716e-ed0f-4dd3-90ce-148681345cbf
	condition:
		any of ($a_*)
 
}