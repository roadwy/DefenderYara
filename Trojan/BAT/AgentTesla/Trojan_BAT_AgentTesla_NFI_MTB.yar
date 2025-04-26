
rule Trojan_BAT_AgentTesla_NFI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 65 31 61 39 38 38 31 63 2d 37 38 38 37 2d 34 63 64 31 2d 61 66 31 37 2d 66 35 62 39 64 61 30 66 62 64 64 36 } //1 $e1a9881c-7887-4cd1-af17-f5b9da0fbdd6
		$a_01_1 = {57 5d b6 c1 09 0b 00 00 00 fa 25 33 00 16 00 00 02 } //1
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_NFI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 1f 7e 8c ?? ?? ?? 01 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 07 11 07 2c 3b 11 04 1f 21 8c ?? ?? ?? 01 09 1f 0e 8c ?? ?? ?? 01 28 ?? ?? ?? 0a 1f 5e 8c ?? ?? ?? 01 28 [0-26] 0a 13 04 00 2b 16 00 11 04 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 00 07 11 05 12 01 } //1
		$a_01_1 = {57 1d b6 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 } //1
		$a_01_2 = {43 6f 6e 76 65 72 74 46 72 6f 6d 55 74 66 33 32 } //1 ConvertFromUtf32
		$a_01_3 = {43 6f 6d 70 61 72 65 4f 62 6a 65 63 74 47 72 65 61 74 65 72 45 71 75 61 6c } //1 CompareObjectGreaterEqual
		$a_01_4 = {46 6f 72 4e 65 78 74 43 68 65 63 6b 4f 62 6a } //1 ForNextCheckObj
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}