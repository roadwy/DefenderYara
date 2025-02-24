
rule Trojan_MacOS_Amos_CV_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CV!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 fb f8 73 50 48 89 d8 48 83 e0 f8 48 83 c0 08 49 89 dc 49 83 cc 07 49 83 fc 17 4c 0f 44 e0 49 ff c4 4c 89 e7 e8 5e 00 00 00 49 89 47 10 49 83 cc 01 4d 89 27 49 89 5f 08 49 89 c7 48 ff c3 } //1
		$a_01_1 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1c 40 f6 c6 02 0f 85 fb 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 d1 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}