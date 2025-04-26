
rule Trojan_BAT_AgentTesla_NMU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {31 38 2e 31 35 36 2e 38 32 2e 38 34 2f 74 69 6e 67 2f 30 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //18.156.82.84/ting/0/loader/uploads/  1
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {50 72 6f 67 72 61 6d } //1 Program
		$a_01_7 = {44 72 61 6d 61 } //1 Drama
		$a_01_8 = {43 6f 6d 65 64 79 } //1 Comedy
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}