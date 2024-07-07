
rule Trojan_BAT_AgentTesla_NMT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {41 62 75 68 63 71 64 7a 66 65 6a 2e 4f 67 61 6f 74 72 68 70 74 73 6a 66 73 76 70 } //Abuhcqdzfej.Ogaotrhptsjfsvp  1
		$a_80_1 = {42 70 6a 79 6d 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Bpjymt.Properties.Resources  1
		$a_80_2 = {4a 64 6e 6b 67 61 78 71 72 61 6d } //Jdnkgaxqram  1
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_80_4 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //GetByteArrayAsync  1
		$a_01_5 = {38 36 32 32 36 2d 30 61 65 34 2d 34 36 37 37 2d 61 35 } //1 86226-0ae4-4677-a5
		$a_01_6 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_7 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}