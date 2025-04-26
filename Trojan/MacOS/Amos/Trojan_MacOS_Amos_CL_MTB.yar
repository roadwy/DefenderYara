
rule Trojan_MacOS_Amos_CL_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CL!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 53 50 48 89 f0 48 c1 e8 3e 75 1a 48 89 f3 48 8d 3c b5 00 00 00 00 e8 89 01 00 00 48 89 da 48 83 c4 08 5b 5d c3 } //1
		$a_01_1 = {55 48 89 e5 41 57 41 56 41 54 53 49 89 f7 48 89 fb 48 89 f7 e8 df 00 00 00 48 83 f8 f0 73 58 49 89 c6 48 83 f8 17 73 10 43 8d 04 36 88 03 48 ff c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}