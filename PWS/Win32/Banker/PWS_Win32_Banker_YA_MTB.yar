
rule PWS_Win32_Banker_YA_MTB{
	meta:
		description = "PWS:Win32/Banker.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 48 52 4f 4d 45 20 50 41 53 53 57 4f 52 44 53 } //01 00  CHROME PASSWORDS
		$a_01_1 = {4f 50 45 52 41 20 50 41 53 53 57 4f 52 44 53 } //01 00  OPERA PASSWORDS
		$a_01_2 = {44 49 41 4c 55 50 2f 52 41 53 2f 56 50 4e 20 50 41 53 53 57 4f 52 44 53 } //01 00  DIALUP/RAS/VPN PASSWORDS
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 5c 54 79 70 65 64 55 52 4c 73 } //01 00  \MicrosoftEdge\TypedURLs
		$a_01_4 = {5c 41 70 70 6c 65 20 43 6f 6d 70 75 74 65 72 5c 50 72 65 66 65 72 65 6e 63 65 73 5c 6b 65 79 63 68 61 69 6e 2e 70 6c 69 73 74 } //01 00  \Apple Computer\Preferences\keychain.plist
		$a_01_5 = {42 45 47 49 4e 20 43 4c 49 50 42 4f 41 52 44 } //00 00  BEGIN CLIPBOARD
	condition:
		any of ($a_*)
 
}