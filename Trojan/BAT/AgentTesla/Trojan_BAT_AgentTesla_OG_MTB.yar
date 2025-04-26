
rule Trojan_BAT_AgentTesla_OG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 5a 69 6c 6c 61 50 72 6f 6a 65 63 74 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 FileZillaProject.frmMain.resources
		$a_81_1 = {46 69 6c 65 5a 69 6c 6c 61 50 72 6f 6a 65 63 74 2e 66 72 6d 44 65 63 6b 56 69 65 77 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 FileZillaProject.frmDeckViewer.resources
		$a_81_2 = {76 65 6c 75 77 65 76 61 6b 61 6e 74 69 65 } //1 veluwevakantie
		$a_81_3 = {46 6f 72 6d 61 74 74 65 72 54 79 70 65 53 74 79 6c 65 } //1 FormatterTypeStyle
		$a_81_4 = {54 69 6d 65 72 30 } //1 Timer0
		$a_81_5 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //1 WSTRBufferMarshaler
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}