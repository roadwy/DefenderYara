
rule Trojan_BAT_AgentTesla_DFO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 66 66 62 66 35 30 65 30 2d 66 36 61 63 2d 34 37 61 30 2d 38 32 63 37 2d 32 61 35 37 63 35 36 65 30 34 39 37 } //1 $ffbf50e0-f6ac-47a0-82c7-2a57c56e0497
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {47 65 74 43 61 6c 6c 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetCallingAssembly
		$a_01_6 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}