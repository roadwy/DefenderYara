
rule Trojan_BAT_AgentTesla_ERO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ERO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 31 35 64 36 31 30 37 37 2d 38 31 36 65 2d 34 61 36 34 2d 62 34 38 35 2d 35 36 61 31 66 64 30 37 62 65 35 64 } //1 $15d61077-816e-4a64-b485-56a1fd07be5d
		$a_01_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_4 = {47 65 74 48 49 4e 53 54 41 4e 43 45 } //1 GetHINSTANCE
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_6 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}