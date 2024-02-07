
rule Trojan_BAT_AgentTesla_OP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //01 00  ISectionEntry
		$a_81_1 = {4d 65 73 73 61 67 65 53 75 72 72 6f 67 61 74 65 46 69 6c 74 65 72 } //01 00  MessageSurrogateFilter
		$a_81_2 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //01 00  Create__Instance__
		$a_81_3 = {4d 79 53 65 74 74 69 6e 67 73 } //01 00  MySettings
		$a_81_4 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_5 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_81_6 = {47 65 74 44 6f 6d 61 69 6e } //00 00  GetDomain
	condition:
		any of ($a_*)
 
}