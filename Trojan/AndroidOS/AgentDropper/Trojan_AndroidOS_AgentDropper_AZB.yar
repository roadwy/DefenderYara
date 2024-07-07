
rule Trojan_AndroidOS_AgentDropper_AZB{
	meta:
		description = "Trojan:AndroidOS/AgentDropper.AZB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 45 57 59 64 57 59 63 6a 70 6c 41 77 51 54 64 67 62 7a 6f 70 6c 5f 39 36 31 38 34 33 } //1 dEWYdWYcjplAwQTdgbzopl_961843
		$a_01_1 = {6d 75 74 69 6e 67 5f 65 6e 61 62 6c 65 64 } //1 muting_enabled
		$a_01_2 = {63 6f 6c 6c 65 63 74 69 6f 6e 73 52 6f 6f 74 } //1 collectionsRoot
		$a_01_3 = {72 65 61 63 74 69 6f 6e 50 69 63 6b 65 72 48 69 6e 74 } //1 reactionPickerHint
		$a_01_4 = {4f 6e 6c 79 49 66 52 75 6e 6e 69 6e 67 } //1 OnlyIfRunning
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}