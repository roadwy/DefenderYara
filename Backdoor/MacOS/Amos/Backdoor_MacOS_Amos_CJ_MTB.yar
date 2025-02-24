
rule Backdoor_MacOS_Amos_CJ_MTB{
	meta:
		description = "Backdoor:MacOS/Amos.CJ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 18 49 89 f6 48 89 fb 0f b6 36 40 f6 c6 01 75 ?? 40 f6 c6 02 0f ?? ?? ?? ?? ?? 0f 57 c0 0f 11 03 48 c7 43 10 00 00 00 00 48 d1 ee } //1
		$a_03_1 = {42 0f b6 0c 22 42 0f b6 44 22 01 8d 79 d0 b2 d0 40 b6 d0 40 80 ff 0a 72 ?? 8d 79 bf 40 b6 c9 40 80 ff 06 72 ?? 8d 79 9f 40 b6 a9 40 80 ff 06 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}