
rule Trojan_BAT_GraceWire_DA_MTB{
	meta:
		description = "Trojan:BAT/GraceWire.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_03_0 = {04 17 9a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 80 ?? ?? ?? 04 20 e4 04 00 00 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 17 9a 6f ?? ?? ?? 0a 26 38 2a 00 00 00 20 04 00 00 00 fe 0e 00 00 fe 0c 00 00 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_4 = {43 6f 6e 76 65 72 74 } //1 Convert
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //1 ToString
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}