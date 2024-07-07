
rule Trojan_BAT_Lokibot_EC_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {47 75 65 73 73 4d 65 6c 6f 64 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 GuessMelody.Properties.Resources.resources
		$a_81_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_2 = {4f 49 48 4a 42 52 53 49 47 4a 4f 49 47 4a 47 } //1 OIHJBRSIGJOIGJG
		$a_81_3 = {49 59 55 51 57 57 51 45 52 57 71 72 77 } //1 IYUQWWQERWqrw
		$a_81_4 = {49 55 59 57 45 57 } //1 IUYWEW
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}