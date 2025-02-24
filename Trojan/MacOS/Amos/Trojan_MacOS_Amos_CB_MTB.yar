
rule Trojan_MacOS_Amos_CB_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d bd 60 ff ff ff e8 5f 14 00 00 48 8d bd 48 ff ff ff e8 53 14 00 00 48 8d 7d a8 e8 4a 14 00 00 31 c0 48 81 c4 b0 00 00 00 5b 41 5e 5d c3 } //1
		$a_01_1 = {55 48 89 e5 41 56 53 48 89 f3 49 89 fe 48 89 f7 e8 6d 13 00 00 4c 89 f7 48 89 de 48 89 c2 5b 41 5e 5d e9 03 10 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}