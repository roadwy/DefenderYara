
rule Trojan_BAT_Lokibot_RW_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 64 37 64 63 33 62 39 31 2d 62 36 62 36 2d 34 62 33 30 2d 39 63 35 30 2d 30 66 64 64 37 38 30 66 38 66 33 63 } //1 $d7dc3b91-b6b6-4b30-9c50-0fdd780f8f3c
		$a_81_1 = {72 65 6d 6f 76 65 5f 4d 6f 75 73 65 43 6c 69 63 6b } //1 remove_MouseClick
		$a_81_2 = {61 64 64 5f 4d 6f 75 73 65 43 6c 69 63 6b } //1 add_MouseClick
		$a_81_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_81_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 } //1 OutputDebugString
		$a_81_5 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_6 = {70 61 73 73 77 6f 72 64 } //1 password
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}