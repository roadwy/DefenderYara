
rule Trojan_BAT_Cerbu_GEN_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.GEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {11 07 1f 10 32 d4 06 16 06 16 95 07 16 95 61 20 a9 f2 0a d2 58 9e 06 17 06 17 95 07 17 95 5a 20 a5 55 19 59 5a 9e 06 18 06 18 95 07 18 95 } //10
		$a_80_1 = {4e 65 6f 53 69 67 6e 54 6f 6f 6c 73 2e 65 78 65 } //NeoSignTools.exe  1
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_3 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //1 ConfusedByAttribute
		$a_01_4 = {44 65 63 6f 64 65 57 69 74 68 4d 61 74 63 68 42 79 74 65 } //1 DecodeWithMatchByte
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}