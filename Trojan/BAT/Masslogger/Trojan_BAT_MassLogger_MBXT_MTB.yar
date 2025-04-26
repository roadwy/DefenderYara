
rule Trojan_BAT_MassLogger_MBXT_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe ?? 16 fe ?? 0d 09 2c } //2
		$a_01_1 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_MassLogger_MBXT_MTB_2{
	meta:
		description = "Trojan:BAT/MassLogger.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 53 00 45 00 31 00 30 00 31 00 5f 00 46 00 69 00 6e 00 61 00 6c 00 5f 00 50 00 72 00 65 00 70 00 } //5 CSE101_Final_Prep
		$a_01_1 = {4c 00 6f 00 61 00 64 } //4
		$a_01_2 = {43 00 61 00 6c 00 63 00 75 00 6c 00 61 00 64 00 6f 00 72 00 61 00 } //3 Calculadora
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //2 InvokeMember
		$a_01_4 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=15
 
}