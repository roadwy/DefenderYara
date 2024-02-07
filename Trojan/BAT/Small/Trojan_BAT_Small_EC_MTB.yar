
rule Trojan_BAT_Small_EC_MTB{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6f 6d 6d 6f 6e 2f 6f 64 73 66 64 72 6f 6d 6d 65 63 6b 2e 61 73 70 78 } //01 00  Common/odsfdrommeck.aspx
		$a_81_1 = {38 65 64 62 32 33 31 36 30 64 31 35 37 31 61 30 } //01 00  8edb23160d1571a0
		$a_81_2 = {43 6f 6d 6d 6f 6e 2f 65 74 67 61 70 61 62 62 74 67 62 65 2e 61 73 70 78 } //01 00  Common/etgapabbtgbe.aspx
		$a_81_3 = {43 6f 6d 6d 6f 6e 2f 64 62 62 72 6e 67 6d 79 69 65 65 77 2e 61 73 70 78 } //01 00  Common/dbbrngmyieew.aspx
		$a_81_4 = {48 74 74 70 53 65 72 76 65 72 55 74 69 6c 69 74 79 } //00 00  HttpServerUtility
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Small_EC_MTB_2{
	meta:
		description = "Trojan:BAT/Small.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 48 00 58 00 4c 00 65 00 67 00 61 00 63 00 79 00 2e 00 65 00 78 00 65 00 } //01 00  PHXLegacy.exe
		$a_01_1 = {64 00 43 00 41 00 72 00 49 00 43 00 49 00 67 00 5a 00 6d 00 6c 00 73 00 5a 00 58 00 4d 00 75 00 49 00 69 00 6b 00 4e 00 43 00 6c 00 64 00 79 00 61 00 58 00 52 00 6c 00 4c 00 55 00 68 00 76 00 63 00 33 00 51 00 67 00 4b 00 43 00 52 00 7a 00 64 00 47 00 39 00 77 00 64 00 47 00 6c 00 74 00 5a 00 53 00 41 00 74 00 49 00 43 00 52 00 7a 00 64 00 47 00 46 00 79 00 64 00 48 00 52 00 70 00 62 00 57 00 55 00 70 00 } //01 00  dCArICIgZmlsZXMuIikNCldyaXRlLUhvc3QgKCRzdG9wdGltZSAtICRzdGFydHRpbWUp
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 } //01 00  DllImportAttribute
		$a_01_4 = {53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 41 75 74 6f 6d 61 74 69 6f 6e 2e 48 6f 73 74 } //01 00  System.Management.Automation.Host
		$a_01_5 = {50 53 48 6f 73 74 55 73 65 72 49 6e 74 65 72 66 61 63 65 } //00 00  PSHostUserInterface
	condition:
		any of ($a_*)
 
}