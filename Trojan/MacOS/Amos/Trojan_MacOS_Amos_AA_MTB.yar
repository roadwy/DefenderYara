
rule Trojan_MacOS_Amos_AA_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 95 0a e7 ff ff 48 89 d6 41 80 f6 68 44 88 b5 09 e7 ff ff 88 9d 08 e7 ff ff 41 0f b6 d6 66 0f 3a 20 c2 07 48 8b 95 20 c6 ff ff 88 95 07 e7 ff ff } //1
		$a_01_1 = {40 0f b6 d6 66 0f 3a 20 c2 08 48 8b 95 50 c6 ff ff 88 95 06 e7 ff ff 40 0f b6 d7 66 0f 3a 20 c2 09 48 8b 95 48 c6 ff ff 88 95 05 e7 ff ff 41 0f b6 d4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}