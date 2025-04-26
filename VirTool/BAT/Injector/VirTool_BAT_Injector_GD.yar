
rule VirTool_BAT_Injector_GD{
	meta:
		description = "VirTool:BAT/Injector.GD,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 49 6b 61 72 75 73 20 2b 20 49 6e 6a 65 63 74 69 6f 6e 73 5c 4d 73 69 5c 4d 73 69 } //1 NoIkarus + Injections\Msi\Msi
		$a_01_1 = {57 69 6e 64 6f 77 73 5c 45 46 53 2e 65 78 65 } //1 Windows\EFS.exe
		$a_01_2 = {53 65 66 75 6c 65 2e 65 78 65 } //1 Sefule.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}