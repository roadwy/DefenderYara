
rule Trojan_BAT_Kryptik_WF_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.WF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b 31 03 09 28 90 02 04 04 09 04 6f 90 02 04 5d 17 d6 28 90 02 04 da 13 04 07 11 04 28 90 02 04 28 90 02 04 28 90 02 04 0b 09 17 d6 0d 09 08 31 cb 90 00 } //10
		$a_03_1 = {0a 0c 08 28 90 02 04 03 6f 90 02 04 6f 90 02 04 0d 07 09 6f 90 02 05 07 18 6f 90 02 05 07 6f 90 02 04 04 16 04 8e 69 6f 90 02 04 13 04 11 04 0a 2b 00 06 2a 90 00 } //10
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  2
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  2
		$a_80_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=14
 
}