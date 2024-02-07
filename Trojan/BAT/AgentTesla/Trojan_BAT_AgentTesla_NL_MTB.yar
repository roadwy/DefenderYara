
rule Trojan_BAT_AgentTesla_NL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 7e 00 00 00 51 00 00 00 f4 00 00 00 b2 01 00 00 f2 00 00 00 cc 00 00 00 5f 00 00 00 02 00 00 00 07 00 00 00 2e 00 00 00 04 00 00 00 09 } //01 00 
		$a_01_1 = {57 95 a2 29 09 03 00 00 00 fa 01 33 00 02 00 00 01 00 00 00 64 00 00 00 41 00 00 00 6a 01 00 00 de 00 00 00 25 02 00 00 96 00 00 00 7e 00 00 00 04 00 00 00 0f 00 00 00 02 00 00 00 03 00 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 33 62 62 62 30 31 36 2d 31 66 64 66 2d 34 61 35 62 2d 61 30 33 32 2d 39 33 61 37 33 31 33 63 65 36 31 61 } //01 00  $13bbb016-1fdf-4a5b-a032-93a7313ce61a
		$a_01_1 = {4c 69 62 72 61 72 79 49 74 65 6d 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  LibraryItems.Properties.Resources.resource
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 65 64 69 63 61 6c 5f 2e 53 74 6f 63 6b 31 30 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Medical_.Stock10.resources
		$a_81_1 = {4d 65 64 69 63 61 6c 5f 2e 45 78 70 69 72 79 31 31 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Medical_.Expiry11.resources
		$a_81_2 = {24 39 36 62 37 61 34 34 38 2d 39 62 63 30 2d 34 65 33 64 2d 61 34 30 62 2d 32 32 62 63 37 64 30 32 39 64 38 64 } //01 00  $96b7a448-9bc0-4e3d-a40b-22bc7d029d8d
		$a_81_3 = {6d 5f 4f 77 6e 65 72 50 61 73 73 34 } //01 00  m_OwnerPass4
		$a_81_4 = {5f 55 73 65 72 41 70 70 6c 69 63 61 74 69 6f 6e 54 72 75 73 74 73 } //01 00  _UserApplicationTrusts
		$a_81_5 = {49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d } //01 00  ICryptoTransform
		$a_81_6 = {53 5f 6e 6f 54 65 78 74 42 6f 78 } //00 00  S_noTextBox
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NL_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f a6 00 00 0a 6f 90 01 03 0a 06 09 06 6f 90 01 03 0a 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 73 90 01 03 0a 13 04 11 04 06 6f 90 01 03 0a 17 73 90 01 03 0a 13 05 02 28 90 01 03 0a 0b 11 05 07 16 07 8e 69 6f 90 01 03 0a 90 00 } //05 00 
		$a_03_1 = {20 5a 05 00 00 28 90 01 03 06 02 28 90 01 03 0a 0b 07 28 90 01 03 0a 3a 90 01 03 00 06 7e 90 01 03 04 02 28 90 01 03 0a 07 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_2 = {50 69 63 6b 65 72 48 6f 73 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PickerHost.g.resources
		$a_01_3 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //00 00  Debugger Detected
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NL_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 54 02 08 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 19 00 00 00 02 00 00 00 01 00 00 00 17 00 00 00 08 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 03 00 00 00 00 00 0a 00 01 00 00 00 00 00 06 } //01 00 
		$a_01_1 = {42 00 71 00 70 00 73 00 71 00 67 00 73 00 6a 00 67 00 61 00 6d 00 6d 00 63 00 00 37 53 00 6b 00 75 00 68 00 63 00 63 00 2e 00 50 00 72 00 6f 00 70 } //01 00 
		$a_01_2 = {53 00 69 00 6c 00 67 00 79 00 62 00 6e 00 71 00 75 00 71 00 70 00 65 00 70 00 6d 00 2e 00 55 00 6c 00 68 00 73 00 74 00 62 00 66 00 66 00 6e 00 73 00 73 00 68 00 65 00 75 00 } //01 00  Silgybnquqpepm.Ulhstbffnssheu
		$a_01_3 = {52 00 70 00 6c 00 70 00 73 00 73 00 73 00 73 00 6e 00 68 00 63 00 76 00 73 00 6a 00 68 00 6d 00 6a 00 65 00 62 00 77 00 67 00 6e 00 } //01 00  Rplpssssnhcvsjhmjebwgn
		$a_01_4 = {4f 00 6a 00 77 00 78 00 70 00 64 00 63 00 6b 00 73 00 2e 00 43 00 76 00 67 00 63 00 69 00 64 00 6e 00 75 00 62 00 65 00 6b 00 6d 00 6b 00 61 00 78 00 6d 00 62 00 79 00 } //0a 00  Ojwxpdcks.Cvgcidnubekmkaxmby
		$a_01_5 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //00 00  cdn.discordapp.com/attachments/
	condition:
		any of ($a_*)
 
}