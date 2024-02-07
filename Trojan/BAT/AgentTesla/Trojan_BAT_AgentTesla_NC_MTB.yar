
rule Trojan_BAT_AgentTesla_NC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 03 17 58 90 01 05 5d 91 0a 16 0b 02 03 28 90 00 } //01 00 
		$a_03_1 = {02 03 1f 16 28 90 01 03 06 0a 06 0b 2b 00 07 2a 90 00 } //01 00 
		$a_01_2 = {20 16 f8 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0a 00 00 05 00 "
		
	strings :
		$a_81_0 = {62 72 6f 6b 65 5f 6d 6f 62 69 6c 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //05 00  broke_mobile.My.Resources
		$a_81_1 = {67 65 74 5f 56 65 72 7a 65 69 63 68 6e 69 73 44 65 72 41 64 6d 69 6e 4b 6f 6e 73 6f 6c 65 } //05 00  get_VerzeichnisDerAdminKonsole
		$a_81_2 = {24 33 66 37 32 66 64 36 37 2d 30 64 62 30 2d 34 61 61 36 2d 38 65 63 34 2d 61 36 35 35 31 38 32 35 63 64 65 39 } //05 00  $3f72fd67-0db0-4aa6-8ec4-a6551825cde9
		$a_81_3 = {67 65 74 5f 4b 65 79 70 61 64 5f 31 } //05 00  get_Keypad_1
		$a_81_4 = {24 56 42 24 4e 6f 6e 4c 6f 63 61 6c 5f 32 } //05 00  $VB$NonLocal_2
		$a_81_5 = {73 65 74 5f 55 70 64 61 74 65 43 6f 6d 6d 61 6e 64 } //01 00  set_UpdateCommand
		$a_81_6 = {4c 6f 67 69 6e 53 63 72 65 65 6e 5f 4c 6f 61 64 } //01 00  LoginScreen_Load
		$a_81_7 = {55 70 64 61 74 65 20 75 73 65 72 73 20 73 65 74 20 70 61 73 73 77 6f 72 64 20 3d 20 27 48 65 6c 6c 6f 31 32 33 27 } //01 00  Update users set password = 'Hello123'
		$a_81_8 = {43 6f 6e 73 6f 6c 61 73 } //01 00  Consolas
		$a_81_9 = {44 65 62 75 67 67 65 72 6c 65 5f 43 6c 6f 73 69 6e 67 } //00 00  Debuggerle_Closing
	condition:
		any of ($a_*)
 
}