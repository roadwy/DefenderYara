
rule TrojanSpy_Win32_AveMaria_ST_{
	meta:
		description = "TrojanSpy:Win32/AveMaria.ST!!AveMaria.ST,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 6c 6c 6f 63 6e 61 6b 2e 78 6d 6c } //ellocnak.xml  01 00 
		$a_80_1 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 } //Elevation:Administrator!new  01 00 
		$a_80_2 = {48 65 79 20 49 27 6d 20 41 64 6d 69 6e 00 } //Hey I'm Admin  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_AveMaria_ST__2{
	meta:
		description = "TrojanSpy:Win32/AveMaria.ST!!AveMaria.ST,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_80_0 = {41 76 65 5f 4d 61 72 69 61 20 53 74 65 61 6c 65 72 } //Ave_Maria Stealer  01 00 
		$a_80_1 = {77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 } //wmic process call create  01 00 
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 } //powershell Add-MpPreference -ExclusionPath   01 00 
		$a_80_3 = {73 65 6c 65 63 74 20 73 69 67 6e 6f 6e 5f 72 65 61 6c 6d 2c 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 66 72 6f 6d 20 77 6f 77 5f 6c 6f 67 69 6e 73 } //select signon_realm, origin_url, username_value, password_value from wow_logins  00 00 
	condition:
		any of ($a_*)
 
}