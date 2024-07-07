
rule Trojan_BAT_Bladabindi_SNGM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SNGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 69 6b 72 61 6c 67 6f 64 65 63 } //2 fikralgodec
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //2 StrReverse
		$a_01_2 = {54 6f 42 79 74 65 } //2 ToByte
		$a_01_3 = {47 65 74 53 74 72 69 6e 67 } //2 GetString
		$a_01_4 = {00 7a 7a 7a 7a 00 } //2 稀空z
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}