
rule Trojan_MacOS_Amos_CW_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CW!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1c 40 f6 c6 02 0f 85 fb 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 d1 ee eb 1c } //1
		$a_01_1 = {41 0f b6 34 14 89 14 b3 41 0f b6 74 14 01 8d 7a 01 89 3c b3 41 0f b6 74 14 02 8d 7a 02 89 3c b3 41 0f b6 74 14 03 8d 7a 03 89 3c b3 48 83 c2 04 48 39 ca 75 cb 48 85 c0 74 16 66 0f 1f 44 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}