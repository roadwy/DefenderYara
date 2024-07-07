
rule Trojan_BAT_AgentTesla_RDY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 62 64 33 62 33 33 64 2d 36 30 36 37 2d 34 30 61 61 2d 39 32 66 38 2d 33 62 62 30 34 35 31 39 33 32 63 62 } //1 ebd3b33d-6067-40aa-92f8-3bb0451932cb
		$a_01_1 = {32 32 6a 61 6e 58 36 34 } //1 22janX64
		$a_01_2 = {41 75 74 6f 4f 70 65 6e } //1 AutoOpen
		$a_01_3 = {41 75 74 6f 43 6c 6f 73 65 } //1 AutoClose
		$a_01_4 = {41 64 64 49 6e } //1 AddIn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}