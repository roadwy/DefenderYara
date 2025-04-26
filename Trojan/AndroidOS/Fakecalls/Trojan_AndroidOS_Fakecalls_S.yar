
rule Trojan_AndroidOS_Fakecalls_S{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.S,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 73 6e 74 65 24 53 65 63 75 72 65 54 79 70 65 24 53 69 67 6e 41 6c 67 6f 72 69 74 68 6d } //1 Tsnte$SecureType$SignAlgorithm
		$a_01_1 = {54 73 6e 74 65 24 63 } //1 Tsnte$c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}