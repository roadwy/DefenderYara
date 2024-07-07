
rule Trojan_BAT_AgentTesla_NVT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 64 31 33 33 36 38 30 35 2d 36 30 33 61 2d 34 34 38 63 2d 61 35 32 31 2d 38 66 34 63 34 39 31 61 62 34 34 39 } //10 $d1336805-603a-448c-a521-8f4c491ab449
		$a_01_1 = {57 9f a2 29 09 1e 00 00 00 fa 01 33 00 16 00 00 01 } //1
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}