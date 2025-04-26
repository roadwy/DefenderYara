
rule Trojan_MacOS_Amos_AJ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AJ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2a 41 00 51 eb 43 00 91 4b 0d 40 b3 0a 69 69 38 6b 01 40 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 49 02 f1 } //1
		$a_01_1 = {bf 6a 34 38 e8 1f 46 39 09 1d 00 13 ea 2f 57 a9 3f 01 00 71 e9 c3 05 91 41 b1 89 9a 62 b1 88 9a e0 43 1f 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}