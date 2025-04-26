
rule Trojan_BAT_AgentTesla_AOA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AOA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_81_0 = {53 69 6d 70 6c 65 55 49 2e 46 6f 72 6d 31 } //1 SimpleUI.Form1
		$a_81_1 = {24 65 65 64 37 35 36 32 38 2d 32 65 61 30 2d 34 34 35 31 2d 38 63 61 34 2d 62 62 36 35 31 61 31 33 63 64 64 62 } //1 $eed75628-2ea0-4451-8ca4-bb651a13cddb
		$a_81_2 = {57 69 6e 43 6f 6e 74 72 6f 6c 73 2e 4c 69 73 74 56 69 65 77 2e 43 6f 6e 74 61 69 6e 65 72 43 6f 6c 75 6d 6e 48 65 61 64 65 72 2e 72 65 73 6f 75 72 63 65 73 e2 80 8e } //1
		$a_81_3 = {57 69 6e 43 6f 6e 74 72 6f 6c 73 2e 4c 69 73 74 56 69 65 77 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 WinControls.ListView.Resources.resource
		$a_81_4 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //1 ReadOnlyDictionary
		$a_81_5 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_6 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //1 GetAssemblies
		$a_81_9 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=8
 
}