
rule Trojan_BAT_AgentTesla_TM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_81_2 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_3 = {5f 58 62 6f 78 46 72 69 65 6e 64 73 } //01 00  _XboxFriends
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_81_5 = {43 6c 69 70 62 6f 61 72 64 50 72 6f 78 79 } //01 00  ClipboardProxy
		$a_81_6 = {43 68 61 74 7a 69 6c 6c 61 20 41 64 76 61 6e 63 65 64 20 43 68 61 74 2d 53 79 73 74 65 6d } //01 00  Chatzilla Advanced Chat-System
		$a_81_7 = {53 74 61 74 75 73 58 62 6f 78 4c 69 76 65 53 69 67 6e 65 64 49 6e } //00 00  StatusXboxLiveSignedIn
	condition:
		any of ($a_*)
 
}