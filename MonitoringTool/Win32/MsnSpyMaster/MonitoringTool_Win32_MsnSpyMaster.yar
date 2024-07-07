
rule MonitoringTool_Win32_MsnSpyMaster{
	meta:
		description = "MonitoringTool:Win32/MsnSpyMaster,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 61 70 70 7d 5c 6d 73 6d 61 73 74 65 72 2e 65 78 65 } //1 {app}\msmaster.exe
		$a_01_1 = {4d 73 6e 20 53 70 79 4d 61 73 74 65 72 } //1 Msn SpyMaster
		$a_01_2 = {53 79 6e 63 73 6f 66 74 20 53 6f 66 74 77 61 72 65 73 20 6f 75 20 73 65 75 73 20 66 6f 72 6e 65 63 65 64 6f 72 65 73 20 72 65 73 70 6f 6e } //1 Syncsoft Softwares ou seus fornecedores respon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule MonitoringTool_Win32_MsnSpyMaster_2{
	meta:
		description = "MonitoringTool:Win32/MsnSpyMaster,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 20 53 70 79 4d 61 73 74 65 72 20 32 30 31 30 } //3 Win SpyMaster 2010
		$a_01_1 = {4d 00 73 00 6e 00 20 00 53 00 70 00 79 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 32 00 30 00 31 00 30 00 } //3 Msn SpyMaster 2010
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 73 00 79 00 6e 00 63 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 2f 00 65 00 73 00 2f 00 73 00 70 00 79 00 6f 00 6e 00 65 00 70 00 72 00 6f 00 2f 00 68 00 65 00 6c 00 70 00 2f 00 } //4 http://www.syncsoft.com.br/es/spyonepro/help/
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4) >=10
 
}
rule MonitoringTool_Win32_MsnSpyMaster_3{
	meta:
		description = "MonitoringTool:Win32/MsnSpyMaster,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 00 79 00 6e 00 63 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 74 00 6f 00 73 00 5c 00 4d 00 73 00 6e 00 20 00 53 00 70 00 79 00 4d 00 61 00 73 00 74 00 65 00 72 00 } //1 syncsoft.com.br\Projetos\Msn SpyMaster
		$a_01_1 = {4f 00 20 00 4d 00 73 00 6e 00 20 00 53 00 70 00 79 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 65 00 73 00 74 00 } //1 O Msn SpyMaster est
		$a_01_2 = {73 00 65 00 6e 00 68 00 61 00 6d 00 61 00 73 00 74 00 65 00 72 00 6d 00 73 00 6e 00 73 00 70 00 79 00 6d 00 61 00 73 00 74 00 65 00 72 00 } //1 senhamastermsnspymaster
		$a_01_3 = {65 00 73 00 20 00 73 00 6f 00 62 00 72 00 65 00 20 00 6f 00 20 00 4d 00 73 00 6e 00 20 00 53 00 70 00 79 00 4d 00 61 00 73 00 74 00 65 00 72 00 } //1 es sobre o Msn SpyMaster
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}