
rule Trojan_MacOS_Amos_DP_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DP!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 89 f0 48 83 e0 f8 48 83 c0 08 4d 89 f4 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 c9 00 00 00 48 89 43 10 49 83 cc 01 4c 89 23 4c 89 73 08 48 89 c3 48 89 df 4c 89 fe 4c 89 f2 } //1
		$a_01_1 = {55 48 89 e5 41 57 41 56 41 54 53 49 89 f7 48 89 fb 48 89 f7 e8 3d 01 00 00 48 83 f8 f8 73 6c 49 89 c6 48 83 f8 17 73 10 43 8d 04 36 88 03 48 ff c3 4d 85 f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}