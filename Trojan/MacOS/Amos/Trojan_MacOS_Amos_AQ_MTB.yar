
rule Trojan_MacOS_Amos_AQ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AQ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c0 e0 02 89 ca c0 ea 04 80 e2 03 08 c2 88 55 d1 c0 e1 04 8a 45 d6 c0 e8 02 24 0f 08 c8 88 45 d2 8b 45 c8 83 f8 02 6a 01 41 5e 44 0f 4d f0 41 ff ce 45 31 ff } //1
		$a_01_1 = {0f 95 c0 0f b6 c0 5d c3 90 48 85 f6 74 13 55 48 89 e5 48 89 f0 0f be 32 48 89 c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}