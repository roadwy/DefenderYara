
rule Trojan_BAT_Redline_GCT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 00 46 00 4e 00 4f 00 54 00 55 00 4a 00 74 00 57 00 46 00 70 00 52 00 54 00 43 00 55 00 3d 00 } //1 UFNOTUJtWFpRTCU=
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {50 53 4e 4d 42 6d 58 5a 51 4c } //1 PSNMBmXZQL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}