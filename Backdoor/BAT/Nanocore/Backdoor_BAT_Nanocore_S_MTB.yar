
rule Backdoor_BAT_Nanocore_S_MTB{
	meta:
		description = "Backdoor:BAT/Nanocore.S!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e } //1 NanoCore.ClientPlugin
		$a_01_1 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e 48 6f 73 74 } //1 NanoCore.ClientPluginHost
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 53 74 61 74 65 43 68 61 6e 67 65 64 } //1 ConnectionStateChanged
		$a_01_3 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //1 get_StartupPath
		$a_01_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_5 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //1 set_CreateNoWindow
		$a_01_6 = {46 69 6c 65 41 63 63 65 73 73 } //1 FileAccess
		$a_01_7 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}