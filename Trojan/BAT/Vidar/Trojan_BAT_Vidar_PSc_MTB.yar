
rule Trojan_BAT_Vidar_PSc_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSc!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 01 09 01 00 00 00 00 00 00 00 00 00 00 01 00 00 00 2d 00 00 00 06 00 00 00 75 00 00 00 19 00 00 00 } //5
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_2 = {64 52 77 65 33 4a 35 75 44 66 66 32 42 76 42 43 77 49 } //1 dRwe3J5uDff2BvBCwI
		$a_01_3 = {66 50 67 48 31 45 6a 45 63 4b 76 6f 5a 34 32 43 76 58 } //1 fPgH1EjEcKvoZ42CvX
		$a_01_4 = {72 32 55 76 6b 41 4f 78 6d 6c 4f 61 4e 44 33 73 4d 63 } //1 r2UvkAOxmlOaND3sMc
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}