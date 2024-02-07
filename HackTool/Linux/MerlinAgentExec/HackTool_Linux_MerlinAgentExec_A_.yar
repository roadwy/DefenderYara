
rule HackTool_Linux_MerlinAgentExec_A_{
	meta:
		description = "HackTool:Linux/MerlinAgentExec.A!!MerlinAgentExec.A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 75 73 72 2f 62 69 6e 2f 6c 65 73 73 70 69 70 65 2e 73 68 } //01 00  /usr/bin/lesspipe.sh
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 4e 65 30 6e 64 30 67 2f 6d 65 72 6c 69 6e 2f 70 6b 67 2f 6d 65 73 73 61 67 65 73 2e 4d 6f 64 75 6c 65 } //01 00  github.com/Ne0nd0g/merlin/pkg/messages.Module
		$a_01_2 = {6d 65 72 6c 69 6e 2f 70 6b 67 2f 6d 65 73 73 61 67 65 73 2e 4b 65 79 45 78 63 68 61 6e 67 65 } //00 00  merlin/pkg/messages.KeyExchange
	condition:
		any of ($a_*)
 
}