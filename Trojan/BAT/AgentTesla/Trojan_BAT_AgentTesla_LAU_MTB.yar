
rule Trojan_BAT_AgentTesla_LAU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6b 6c 69 6e 69 6b 64 62 2e 6d 64 66 } //1 klinikdb.mdf
		$a_01_1 = {6d 6f 64 65 6c 31 2e 63 6f 6e 74 65 78 74 2e 74 74 } //1 model1.context.tt
		$a_01_2 = {6d 6f 64 65 6c 31 2e 74 74 } //1 model1.tt
		$a_01_3 = {6b 6c 69 6e 69 6b 64 62 5f 6c 6f 67 2e 6c 64 66 } //1 klinikdb_log.ldf
		$a_01_4 = {4d 6f 64 65 6c 31 2e 73 73 64 6c } //1 Model1.ssdl
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_9 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}