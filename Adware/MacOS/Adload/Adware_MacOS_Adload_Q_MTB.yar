
rule Adware_MacOS_Adload_Q_MTB{
	meta:
		description = "Adware:MacOS/Adload.Q!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8a 13 4c 89 e6 4c 89 d7 0f 1f 80 00 00 00 00 48 89 f1 48 89 fe 48 c1 ee 3f 48 01 fe 48 d1 fe 48 89 f0 48 f7 d0 48 01 f8 38 14 31 48 0f 4d c6 48 8d 74 31 01 48 0f 4d f1 48 89 c7 48 85 c0 75 ?? 4c 39 c6 74 ?? 38 16 7f ?? 49 ff c3 4d 39 f3 } //1
		$a_03_1 = {4d 89 de e9 ?? ?? ?? ?? 4d 8b 54 24 10 49 83 fa 11 0f 83 ?? ?? ?? ?? 4f 8d 04 14 4d 85 d2 0f 84 ?? ?? ?? ?? 4d 89 eb 66 2e 0f 1f 84 00 00 00 00 00 ?? 41 8a 13 4c 89 e6 4c 89 d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}