
rule Trojan_BAT_AgentTesla_JDC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {0b 03 0c 04 0d 08 13 04 2b 11 07 02 11 04 9a 6f ?? ?? ?? 0a 26 11 04 17 d6 13 04 11 04 09 31 ea } //10
		$a_81_1 = {42 72 69 64 67 65 48 69 73 74 6f 72 79 46 6f 72 6d } //1 BridgeHistoryForm
		$a_81_2 = {6d 5f 42 72 69 64 67 65 4e 6f 74 65 45 64 69 74 46 6f 72 6d } //1 m_BridgeNoteEditForm
		$a_81_3 = {6d 5f 42 72 69 64 67 65 41 64 64 46 6f 72 6d } //1 m_BridgeAddForm
		$a_81_4 = {24 30 30 30 32 30 38 31 33 2d 30 30 30 30 2d 30 30 30 30 2d 63 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 } //1 $00020813-0000-0000-c000-000000000046
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}