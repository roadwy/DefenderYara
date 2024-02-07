
rule Trojan_BAT_AgentTesla_NTS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 05 00 00 04 72 90 01 03 70 28 90 01 03 0a 39 90 01 03 00 7e 90 01 03 04 72 90 01 03 70 6f 90 01 03 0a 2c 38 7e 90 01 03 04 7e 90 01 03 04 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 0a 28 90 01 03 0a 26 38 90 01 03 00 7e 90 01 03 04 90 00 } //01 00 
		$a_01_1 = {41 62 61 64 64 6f 6e 44 72 6f 70 70 65 72 2d 6d 61 69 6e } //01 00  AbaddonDropper-main
		$a_01_2 = {4b 72 73 74 6f } //00 00  Krsto
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NTS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 37 39 31 37 32 42 31 33 2d 45 44 42 41 2d 34 30 39 36 2d 42 37 32 35 2d 38 45 39 32 42 37 33 30 42 32 42 41 } //01 00  $79172B13-EDBA-4096-B725-8E92B730B2BA
		$a_01_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 33 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ClassLibrary3.Resources.resources
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_3 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}