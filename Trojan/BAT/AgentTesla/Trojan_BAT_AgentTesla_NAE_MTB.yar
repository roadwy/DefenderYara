
rule Trojan_BAT_AgentTesla_NAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 11 01 28 0d 00 00 06 13 02 38 ?? 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 13 01 20 ?? 00 00 00 } //5
		$a_01_1 = {50 75 61 66 6f 77 72 } //1 Puafowr
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAE_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 36 00 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a fe ?? ?? 00 fe ?? ?? 00 6f ?? ?? 00 0a d4 8d ?? ?? 00 01 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? 00 00 fe ?? ?? 00 8e 69 6f ?? ?? 00 0a 26 14 fe ?? ?? 00 73 ?? ?? 00 0a fe ?? ?? 00 fe ?? ?? 00 73 ?? ?? 00 0a fe ?? ?? 00 fe ?? ?? 00 20 ?? ?? 00 00 73 ?? ?? 00 0a fe ?? ?? 00 } //5
		$a_01_1 = {75 6e 70 61 63 6b 6d 65 65 } //1 unpackmee
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_NAE_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_1 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {00 49 5f 5f 5f 5f 5f 5f 5f 49 00 } //1
		$a_01_4 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //1 䤀彟彟彟彟I
		$a_01_5 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //1
		$a_01_6 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //1 䤀彟彟彟彟彟I
		$a_01_7 = {00 49 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 49 00 } //1
		$a_01_8 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}