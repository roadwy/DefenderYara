
rule Trojan_BAT_Remcos_EG_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 0c 00 00 "
		
	strings :
		$a_81_0 = {66 69 72 73 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //20 first.Properties.Resources
		$a_81_1 = {47 65 74 2b 2b 2b 54 79 70 65 } //1 Get+++Type
		$a_81_2 = {41 73 73 2b 2b 2b 65 6d 62 6c 79 } //1 Ass+++embly
		$a_81_3 = {54 6f 41 2b 2b 2b 72 72 61 79 } //1 ToA+++rray
		$a_81_4 = {4c 6f 61 2b 2b 2b 64 } //1 Loa+++d
		$a_81_5 = {45 6e 74 72 2b 2b 2b 79 50 6f 69 6e 74 } //1 Entr+++yPoint
		$a_81_6 = {49 6e 2b 2b 2b 76 6f 6b 65 } //1 In+++voke
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_8 = {41 70 70 65 6e 64 } //1 Append
		$a_81_9 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_10 = {43 6f 6e 63 61 74 } //1 Concat
		$a_81_11 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=31
 
}