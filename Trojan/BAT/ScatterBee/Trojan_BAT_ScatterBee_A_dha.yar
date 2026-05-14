
rule Trojan_BAT_ScatterBee_A_dha{
	meta:
		description = "Trojan:BAT/ScatterBee.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 72 6f 70 4c 6f 61 64 2e 43 6f 6d 6d 61 6e 64 2b 3c 6c 6f 61 64 45 78 65 63 } //1 DropLoad.Command+<loadExec
		$a_01_1 = {44 72 6f 70 4c 6f 61 64 2e 43 6f 6d 6d 61 6e 64 2b 3c 4d 61 6b 65 48 74 74 70 52 65 71 75 65 73 74 } //1 DropLoad.Command+<MakeHttpRequest
		$a_01_2 = {44 72 6f 70 4c 6f 61 64 2e 52 65 71 75 65 73 74 2b 3c 47 65 74 54 65 6c 65 67 72 61 6d 54 61 73 6b } //1 DropLoad.Request+<GetTelegramTask
		$a_01_3 = {44 72 6f 70 4c 6f 61 64 2e 43 6f 6d 6d 61 6e 64 2b 3c 45 78 65 63 75 74 65 41 73 73 65 6d 62 6c 79 } //1 DropLoad.Command+<ExecuteAssembly
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}