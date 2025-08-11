
rule Trojan_MacOS_Amos_EE_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EE!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 28 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 1d 40 f6 c6 02 0f 85 e4 00 00 00 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 48 d1 ee eb 1c } //1
		$a_01_1 = {45 31 ff 45 31 e4 eb 14 66 66 66 2e 0f 1f 84 00 00 00 00 00 49 83 c4 02 49 83 c7 fe 45 0f b6 2e 41 f6 c5 01 75 0e 49 d1 ed 4d 39 ec 73 79 48 8b 75 b8 eb 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}