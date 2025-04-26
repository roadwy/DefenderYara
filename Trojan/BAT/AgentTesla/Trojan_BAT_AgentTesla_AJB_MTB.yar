
rule Trojan_BAT_AgentTesla_AJB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {48 6f 6c 69 64 61 79 2e 41 62 6f 75 74 42 6f 78 2e 72 65 73 6f 75 72 63 65 73 } //1 Holiday.AboutBox.resources
		$a_81_1 = {48 6f 6c 69 64 61 79 2e 41 64 64 53 6f 75 72 63 65 2e 72 65 73 6f 75 72 63 65 73 } //1 Holiday.AddSource.resources
		$a_81_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_3 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_4 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //1 ReadOnlyDictionary
		$a_81_5 = {42 75 69 6c 64 65 72 49 6e 73 74 61 6e 74 69 61 74 69 6f 6e } //1 BuilderInstantiation
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_8 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_9 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_10 = {43 72 65 61 74 65 44 6f 6d 61 69 6e } //1 CreateDomain
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}