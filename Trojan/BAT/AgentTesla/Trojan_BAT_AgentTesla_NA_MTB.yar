
rule Trojan_BAT_AgentTesla_NA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {25 47 11 0b 11 0f 11 0b 8e 69 5d 91 61 d2 52 00 90 01 02 17 58 13 0f 11 0f 11 0a 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 7c 3b 02 70 17 8d 90 01 03 01 25 16 11 01 a2 25 13 02 90 00 } //01 00 
		$a_01_1 = {51 00 51 00 51 00 57 00 57 00 57 00 } //01 00  QQQWWW
		$a_01_2 = {62 00 6c 00 6e 00 41 00 6f 00 79 00 58 00 } //00 00  blnAoyX
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 07 6f 2c 00 00 0a 0c 20 90 01 03 ff 28 90 01 03 0a fe 90 01 02 00 38 90 01 03 00 90 00 } //01 00 
		$a_01_1 = {70 75 62 6c 69 63 2e 63 6c 61 73 73 2e 4d 61 69 6e 2e 48 65 6c 6c 6f 57 6f 72 6c 64 2e 6d 6f 64 75 6c 65 31 33 } //00 00  public.class.Main.HelloWorld.module13
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 07 25 1a 58 13 07 4b 11 07 25 1a 58 13 07 4b 5a 13 11 11 11 20 90 01 03 dc 33 2d 08 07 2d 07 90 00 } //01 00 
		$a_01_1 = {4d 4b 4d 4e 6e 4e 39 38 38 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  MKMNnN988.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8f 0b 00 00 01 25 71 90 01 01 00 00 01 fe 90 01 02 00 fe 90 01 02 00 20 90 01 01 00 00 00 5d 91 61 d2 81 90 01 01 00 00 01 20 90 01 01 00 00 00 fe 90 01 02 00 00 fe 90 01 02 00 20 90 01 01 00 00 00 fe 01 39 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_1 = {46 6c 61 6d 65 41 73 73 65 6d 62 6c 69 65 73 } //00 00  FlameAssemblies
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 40 00 00 0a 0a 28 90 01 01 00 00 06 0b 07 1f 20 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 1f 10 8d 90 01 01 00 00 01 25 d0 90 01 01 00 00 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 0c 08 02 16 02 8e 69 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {43 68 75 61 6e 67 2e 50 72 69 6e 74 65 72 2e 43 6c 69 65 6e 74 55 6e 69 6e 73 74 61 6c 6c } //00 00  Chuang.Printer.ClientUninstall
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NA_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 09 00 00 05 00 "
		
	strings :
		$a_81_0 = {44 65 6c 6f 32 4d 61 69 6c 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //05 00  Delo2Mail.My.Resources
		$a_81_1 = {44 65 6c 6f 32 4d 61 69 6c 2e 42 61 69 64 75 } //05 00  Delo2Mail.Baidu
		$a_81_2 = {67 65 74 5f 53 4d 54 50 50 61 73 73 77 6f 72 64 } //01 00  get_SMTPPassword
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_81_4 = {41 74 74 61 63 68 6d 65 6e 74 46 69 6c 65 } //01 00  AttachmentFile
		$a_81_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  ShellExecute
		$a_81_6 = {52 53 45 64 69 74 50 61 72 61 6d 65 74 65 72 73 5f 4c 6f 61 64 } //01 00  RSEditParameters_Load
		$a_81_7 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_8 = {49 43 72 65 64 65 6e 74 69 61 6c 73 42 79 48 6f 73 74 } //00 00  ICredentialsByHost
	condition:
		any of ($a_*)
 
}