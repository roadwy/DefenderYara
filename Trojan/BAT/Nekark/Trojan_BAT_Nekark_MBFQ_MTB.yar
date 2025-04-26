
rule Trojan_BAT_Nekark_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/Nekark.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 64 64 66 68 65 66 64 64 66 66 6a 66 73 66 6b 66 67 73 61 63 73 61 66 70 } //10 sddfhefddffjfsfkfgsacsafp
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}