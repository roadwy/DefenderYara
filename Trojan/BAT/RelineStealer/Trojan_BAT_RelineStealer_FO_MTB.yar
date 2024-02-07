
rule Trojan_BAT_RelineStealer_FO_MTB{
	meta:
		description = "Trojan:BAT/RelineStealer.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {61 70 69 2e 69 70 2e 73 62 2f 69 70 } //api.ip.sb/ip  01 00 
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 65 6e 74 73 5c 53 74 61 72 74 4d 65 6e 75 49 6e 74 65 72 6e 65 74 } //SOFTWARE\Clients\StartMenuInternet  01 00 
		$a_80_2 = {7b 30 7d 5c 46 69 6c 65 5a 69 6c 6c 61 5c 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //{0}\FileZilla\recentservers.xml  01 00 
		$a_80_3 = {75 73 65 72 2e 63 6f 6e 66 69 67 } //user.config  01 00 
		$a_80_4 = {63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 } //cookies.sqlite  01 00 
		$a_01_5 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 } //01 00  GetLogicalDrives
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_80_7 = {50 72 6f 66 69 6c 65 5f 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 } //Profile_encrypted_value  01 00 
		$a_80_8 = {77 61 61 73 66 6c 6c 65 61 73 66 74 2e 64 61 74 61 73 66 } //waasflleasft.datasf  01 00 
		$a_80_9 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 54 52 65 70 6c 61 63 65 6f 6b 52 65 70 6c 61 63 65 65 6e 52 65 70 6c 61 63 65 73 2e 74 52 65 70 6c 61 63 65 78 74 } //AppData\Roaming\TReplaceokReplaceenReplaces.tReplacext  00 00 
	condition:
		any of ($a_*)
 
}