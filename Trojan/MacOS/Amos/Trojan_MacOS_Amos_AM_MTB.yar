
rule Trojan_MacOS_Amos_AM_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AM!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 f9 41 ff c7 88 44 0d d5 41 83 ff 03 75 69 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 89 c2 c0 ea 06 c0 e1 02 08 d1 80 e1 3f } //1
		$a_01_1 = {89 c1 c6 44 0d d5 00 ff c0 83 f8 03 75 f2 8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 45 85 ff 78 3b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}