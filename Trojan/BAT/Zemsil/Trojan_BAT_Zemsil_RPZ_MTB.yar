
rule Trojan_BAT_Zemsil_RPZ_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {45 64 65 6e 54 65 73 74 4d 65 74 68 6f 64 } //1 EdenTestMethod
		$a_01_1 = {45 78 65 63 75 74 65 53 68 65 6c 6c 43 6f 64 65 } //1 ExecuteShellCode
		$a_01_2 = {43 70 75 55 73 61 67 65 } //1 CpuUsage
		$a_01_3 = {50 61 6e 65 6c 53 68 65 6c 6c 43 6f 64 65 45 6e 63 72 79 70 74 69 6f 6e 4d 6f 64 75 6c 65 } //1 PanelShellCodeEncryptionModule
		$a_01_4 = {50 61 6e 65 6c 53 68 65 6c 6c 43 6f 64 65 4c 6f 61 64 65 72 4d 6f 64 75 6c 65 } //1 PanelShellCodeLoaderModule
		$a_01_5 = {43 75 72 72 65 6e 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 } //1 CurrentComputerName
		$a_01_6 = {45 64 65 6e 50 72 6f 6a 65 63 74 43 6f 6e 66 69 67 } //1 EdenProjectConfig
		$a_01_7 = {54 65 73 74 57 65 62 53 68 65 6c 6c } //1 TestWebShell
		$a_01_8 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 } //1 explorer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}