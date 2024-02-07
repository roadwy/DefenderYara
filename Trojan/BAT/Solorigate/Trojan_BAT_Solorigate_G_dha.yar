
rule Trojan_BAT_Solorigate_G_dha{
	meta:
		description = "Trojan:BAT/Solorigate.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 } //01 00  CompileAssemblyFromSource
		$a_00_1 = {43 72 65 61 74 65 43 6f 6d 70 69 6c 65 72 } //01 00  CreateCompiler
		$a_01_2 = {63 6c 61 7a 7a } //01 00  clazz
		$a_00_3 = {2f 00 2f 00 4e 00 65 00 74 00 50 00 65 00 72 00 66 00 4d 00 6f 00 6e 00 2f 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 2f 00 4e 00 6f 00 4c 00 6f 00 67 00 6f 00 2e 00 67 00 69 00 66 00 } //01 00  //NetPerfMon//images//NoLogo.gif
		$a_00_4 = {41 00 70 00 70 00 5f 00 57 00 65 00 62 00 5f 00 6c 00 6f 00 67 00 6f 00 69 00 6d 00 61 00 67 00 65 00 68 00 61 00 6e 00 64 00 6c 00 65 00 72 00 2e 00 61 00 73 00 68 00 78 00 2e 00 62 00 36 00 30 00 33 00 31 00 38 00 39 00 36 00 2e 00 64 00 6c 00 6c 00 } //00 00  App_Web_logoimagehandler.ashx.b6031896.dll
	condition:
		any of ($a_*)
 
}