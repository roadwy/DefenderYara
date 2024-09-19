
rule Adware_MacOS_Adload_I_MTB{
	meta:
		description = "Adware:MacOS/Adload.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 55 41 54 53 48 83 ec 48 49 89 d7 49 39 d0 74 ?? 48 89 ca 48 29 f2 48 c1 e2 05 4c 89 c0 48 2b 01 48 c1 f8 04 48 01 d0 4c 89 f9 48 2b 0e 48 c1 f9 04 48 29 c8 } //1
		$a_03_1 = {48 8b 4f 08 4c 8b 4f 10 4d 89 ce 49 29 ce 4c 89 f3 48 c1 e3 05 48 ff cb 4d 85 f6 49 0f 44 de 48 8b 57 20 48 89 7d b0 48 8b 7f 28 48 01 d7 48 29 fb 48 29 d8 4c 89 45 a0 0f ?? ?? ?? ?? ?? 48 89 75 ?? 31 ff 49 39 c9 40 0f 94 c7 48 01 f8 48 89 c7 48 c1 ef 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}