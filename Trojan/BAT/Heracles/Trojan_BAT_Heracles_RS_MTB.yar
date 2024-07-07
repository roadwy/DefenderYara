
rule Trojan_BAT_Heracles_RS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4d 65 74 61 6c 2e 64 6c 6c } //Metal.dll  1
		$a_80_1 = {50 65 73 74 69 63 69 64 65 20 41 70 70 6c 69 63 61 74 6f 72 } //Pesticide Applicator  1
		$a_80_2 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 31 30 30 30 39 2d 31 31 31 31 32 7d } //{11111-22222-10009-11112}  1
		$a_80_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //System.Reflection  1
		$a_80_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //GetExecutingAssembly  1
		$a_80_5 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } //GetDelegateForFunctionPointer  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule Trojan_BAT_Heracles_RS_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.RS!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 28 02 00 00 06 0c 28 27 00 00 0a 06 6f 28 00 00 0a 0d 73 29 00 00 0a 13 04 16 13 05 2b 1d } //5
		$a_01_1 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f 2a 00 00 0a 11 05 17 58 13 05 11 05 08 8e 69 32 dc } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}