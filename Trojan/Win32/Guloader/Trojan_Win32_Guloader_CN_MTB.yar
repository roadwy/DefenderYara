
rule Trojan_Win32_Guloader_CN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 72 6f 6d 6c 65 72 65 76 6f 6c 76 65 72 73 5c 53 70 65 63 73 61 72 74 69 6e 65 36 35 2e 69 6e 69 } //01 00  tromlerevolvers\Specsartine65.ini
		$a_01_1 = {6d 6f 63 68 69 6c 61 5c 62 6f 72 6f 66 6c 75 6f 72 69 6e 2e 69 6e 69 } //01 00  mochila\borofluorin.ini
		$a_01_2 = {72 65 6b 6c 61 6d 65 66 69 6c 6d 65 6e 5c 42 72 6e 65 74 69 6c 73 6b 75 64 64 65 74 73 2e 73 6d 75 } //01 00  reklamefilmen\Brnetilskuddets.smu
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 6e 67 6c 65 70 65 72 73 6f 6e 73 5c 75 6e 64 76 69 67 65 6d 61 6e 76 72 65 72 } //01 00  Software\nglepersons\undvigemanvrer
		$a_01_4 = {6b 6e 61 72 6c 25 5c 41 6e 74 65 72 65 66 6f 72 6d 61 74 69 6f 6e 61 6c 2e 74 72 69 } //00 00  knarl%\Antereformational.tri
	condition:
		any of ($a_*)
 
}