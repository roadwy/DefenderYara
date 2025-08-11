
rule Trojan_MacOS_Amos_EC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.EC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 5d 80 0f 1f 00 43 8b 04 27 43 2b 04 2f 41 33 06 0f be f0 48 89 df } //2
		$a_03_1 = {48 89 c2 4c 09 e2 48 c1 ea 20 74 ?? 31 d2 49 f7 f4 48 89 d0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}