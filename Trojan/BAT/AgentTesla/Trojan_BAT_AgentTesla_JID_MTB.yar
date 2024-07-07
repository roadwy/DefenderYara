
rule Trojan_BAT_AgentTesla_JID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f } //1
		$a_81_1 = {43 3a 5c 64 6e 77 61 69 6f 64 77 61 6e 64 77 61 6e 69 6f 64 61 77 6e 6f 64 77 61 6e 64 61 77 6f 61 6e 67 72 64 70 5c 64 77 61 64 2e 65 78 65 } //1 C:\dnwaiodwandwaniodawnodwandawoangrdp\dwad.exe
		$a_81_2 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //1 DetectVirtualMachine
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 } //1 DownloadPayload
		$a_81_4 = {52 75 6e 50 61 79 6c 6f 61 64 } //1 RunPayload
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //1 GetFolderPath
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}