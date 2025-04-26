
rule Trojan_BAT_AgentTesla_OP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //1 ISectionEntry
		$a_81_1 = {4d 65 73 73 61 67 65 53 75 72 72 6f 67 61 74 65 46 69 6c 74 65 72 } //1 MessageSurrogateFilter
		$a_81_2 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_81_3 = {4d 79 53 65 74 74 69 6e 67 73 } //1 MySettings
		$a_81_4 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_5 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_6 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}