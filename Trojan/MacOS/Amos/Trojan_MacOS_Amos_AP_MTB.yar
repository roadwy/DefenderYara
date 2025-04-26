
rule Trojan_MacOS_Amos_AP_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AP!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 09 48 8b 7d e0 e8 ea 04 00 00 48 89 df e8 e2 04 00 00 31 c0 48 83 c4 38 5b 41 5e 41 5f 5d c3 48 8d 35 ac 07 00 00 e8 9d 00 00 00 48 89 c7 e8 c5 00 00 00 bf 01 00 00 00 e8 db 04 00 00 } //1
		$a_01_1 = {48 8b 7d c0 4d 01 fe 41 81 e5 b0 00 00 00 41 83 fd 20 4c 89 fa 49 0f 44 d6 44 0f be c8 4c 89 fe 4c 89 f1 4d 89 e0 e8 9e 00 00 00 48 85 c0 75 17 48 8b 03 48 8b 40 e8 48 8d 3c 03 8b 74 03 20 83 ce 05 e8 82 02 00 00 48 8d 7d b0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}