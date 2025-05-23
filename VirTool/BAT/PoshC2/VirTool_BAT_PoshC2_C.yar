
rule VirTool_BAT_PoshC2_C{
	meta:
		description = "VirTool:BAT/PoshC2.C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 00 6f 00 73 00 68 00 2d 00 44 00 65 00 6c 00 65 00 74 00 65 00 } //1 Posh-Delete
		$a_01_1 = {50 00 6f 00 73 00 68 00 43 00 32 00 20 00 2d 00 20 00 43 00 6f 00 72 00 65 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 } //1 PoshC2 - Core Module
		$a_01_2 = {64 00 72 00 6f 00 70 00 70 00 65 00 72 00 5f 00 63 00 73 00 } //1 dropper_cs
		$a_01_3 = {43 6f 72 65 2e 57 4d 49 } //1 Core.WMI
		$a_01_4 = {43 6f 72 65 2e 49 6e 6a 65 63 74 69 6f 6e } //1 Core.Injection
		$a_01_5 = {43 6f 72 65 2e 41 72 70 } //1 Core.Arp
		$a_01_6 = {43 6f 72 65 2e 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 72 } //1 Core.ProcessHandler
		$a_01_7 = {43 6f 72 65 2e 43 72 65 64 50 6f 70 70 65 72 } //1 Core.CredPopper
		$a_01_8 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed } //1
		$a_01_9 = {48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}