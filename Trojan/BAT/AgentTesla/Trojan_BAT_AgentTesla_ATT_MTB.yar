
rule Trojan_BAT_AgentTesla_ATT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ATT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {18 19 8d 17 00 00 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_01_5 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}