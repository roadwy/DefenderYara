
rule Trojan_BAT_StealC_MBXN_MTB{
	meta:
		description = "Trojan:BAT/StealC.MBXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 9d b6 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 } //2
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 .g.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}