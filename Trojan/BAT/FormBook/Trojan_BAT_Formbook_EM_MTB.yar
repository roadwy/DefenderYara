
rule Trojan_BAT_Formbook_EM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 61 32 37 63 63 66 30 37 2d 32 62 64 35 2d 34 30 64 63 2d 39 36 37 39 2d 35 30 35 64 63 61 39 39 66 61 66 34 } //01 00  $a27ccf07-2bd5-40dc-9679-505dca99faf4
		$a_81_1 = {47 45 53 54 54 49 4f 4e 5f 64 65 73 5f 48 4f 54 45 4c } //01 00  GESTTION_des_HOTEL
		$a_81_2 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_81_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_81_4 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_5 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_EM_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 35 32 38 30 33 37 36 33 2d 30 63 33 38 2d 34 35 64 30 2d 38 64 66 39 2d 37 39 62 65 34 31 33 32 37 66 37 32 } //01 00  $52803763-0c38-45d0-8df9-79be41327f72
		$a_81_1 = {43 61 6c 63 75 6c 61 74 6f 72 2e 4d 61 69 6e 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Calculator.MainMenu.resources
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_4 = {41 63 74 69 76 61 74 65 } //01 00  Activate
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_6 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerBrowsableAttribute
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_EM_MTB_3{
	meta:
		description = "Trojan:BAT/Formbook.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {47 51 6b 69 4c 2e 70 64 62 } //03 00  GQkiL.pdb
		$a_81_1 = {61 48 52 30 63 44 6f 76 4c 32 39 73 65 58 42 68 64 47 67 75 59 32 39 74 4c 31 46 7a 55 6d 39 42 4c 6d 56 34 5a 51 3d 3d } //03 00  aHR0cDovL29seXBhdGguY29tL1FzUm9BLmV4ZQ==
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //03 00  DownloadData
		$a_81_3 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //03 00  get_ExecutablePath
		$a_81_4 = {44 65 73 69 67 6e 50 61 74 74 65 72 6e 73 2e 47 61 6e 67 4f 66 46 6f 75 72 2e 53 74 72 75 63 74 75 72 61 6c 2e 42 72 69 64 67 65 } //03 00  DesignPatterns.GangOfFour.Structural.Bridge
		$a_81_5 = {74 65 73 74 69 6e 67 41 53 50 4e 45 54 4d 56 43 57 65 62 41 50 49 } //03 00  testingASPNETMVCWebAPI
		$a_81_6 = {43 6f 6d 6d 6f 6e 44 65 73 69 67 6e 50 61 74 74 65 72 6e 73 2e 69 6e 74 72 6f 44 6f 74 4e 65 74 43 6f 72 65 57 69 74 68 4d 56 43 } //00 00  CommonDesignPatterns.introDotNetCoreWithMVC
	condition:
		any of ($a_*)
 
}