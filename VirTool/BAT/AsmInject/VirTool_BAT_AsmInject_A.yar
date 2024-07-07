
rule VirTool_BAT_AsmInject_A{
	meta:
		description = "VirTool:BAT/AsmInject.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 4c 00 6f 00 61 00 64 00 65 00 72 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2c 00 20 00 43 00 75 00 6c 00 74 00 75 00 72 00 65 00 3d 00 6e 00 65 00 75 00 74 00 72 00 61 00 6c 00 2c 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 6e 00 75 00 6c 00 6c 00 } //1
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 4c 69 62 72 61 72 79 } //1 InjectionLibrary
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule VirTool_BAT_AsmInject_A_2{
	meta:
		description = "VirTool:BAT/AsmInject.A,SIGNATURE_TYPE_PEHSTR,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 65 00 72 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2c 00 20 00 43 00 75 00 6c 00 74 00 75 00 72 00 65 00 3d 00 6e 00 65 00 75 00 74 00 72 00 61 00 6c 00 2c 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 6e 00 75 00 6c 00 6c 00 } //100 Loader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
		$a_01_1 = {7c 00 53 00 65 00 6c 00 66 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 7c 00 46 00 61 00 6c 00 73 00 65 00 7c 00 46 00 61 00 6c 00 73 00 65 00 7c 00 } //1 |Self Inject|False|False|
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1) >=101
 
}
rule VirTool_BAT_AsmInject_A_3{
	meta:
		description = "VirTool:BAT/AsmInject.A,SIGNATURE_TYPE_PEHSTR,64 00 64 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 65 00 72 00 2c 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 2c 00 20 00 43 00 75 00 6c 00 74 00 75 00 72 00 65 00 3d 00 6e 00 65 00 75 00 74 00 72 00 61 00 6c 00 2c 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 4b 00 65 00 79 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 6e 00 75 00 6c 00 6c 00 } //1 Loader, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
		$a_01_1 = {7c 00 53 00 65 00 6c 00 66 00 20 00 49 00 6e 00 6a 00 65 00 63 00 74 00 7c 00 46 00 61 00 6c 00 73 00 65 00 7c 00 46 00 61 00 6c 00 73 00 65 00 7c 00 } //1 |Self Inject|False|False|
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=100
 
}