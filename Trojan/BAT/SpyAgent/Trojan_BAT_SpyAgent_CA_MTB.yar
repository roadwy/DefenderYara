
rule Trojan_BAT_SpyAgent_CA_MTB{
	meta:
		description = "Trojan:BAT/SpyAgent.CA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 73 50 72 6f 78 79 44 65 74 65 63 74 65 64 55 73 69 6e 67 57 4d 49 } //1 IsProxyDetectedUsingWMI
		$a_01_1 = {43 68 65 63 6b 46 6f 72 56 4d 48 61 72 64 77 61 72 65 } //1 CheckForVMHardware
		$a_01_2 = {44 65 74 65 63 74 53 61 6e 64 42 6f 78 42 79 44 6c 6c } //1 DetectSandBoxByDll
		$a_01_3 = {44 65 74 65 63 74 4d 6f 6e 69 74 69 72 69 6e 67 54 6f 6f 6c } //1 DetectMonitiringTool
		$a_01_4 = {43 68 65 63 6b 46 6f 72 56 4d 50 72 6f 63 65 73 73 65 73 } //1 CheckForVMProcesses
		$a_01_5 = {43 68 65 63 6b 46 6f 72 56 50 53 45 6e 76 69 72 6f 6e 6d 65 6e 74 } //1 CheckForVPSEnvironment
		$a_01_6 = {49 73 50 72 6f 78 79 44 65 74 65 63 74 65 64 55 73 69 6e 67 52 65 67 69 73 74 72 79 } //1 IsProxyDetectedUsingRegistry
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}