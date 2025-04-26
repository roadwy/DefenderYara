
rule Trojan_MacOS_Amos_V_MTB{
	meta:
		description = "Trojan:MacOS/Amos.V!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 45 d5 8a 4d d6 89 c2 c0 ea 02 88 55 d1 89 ca c0 ea 04 c0 e0 04 08 d0 24 3f 88 45 d2 8a 45 d7 c0 e8 06 c0 e1 02 08 c1 80 e1 3f 88 4d d3 4d 63 f7 45 31 e4 } //1
		$a_01_1 = {66 c7 85 08 fe ff ff 32 6e 6a 01 58 48 83 f8 0b 74 12 8a 8d 00 fe ff ff 30 8c 05 00 fe ff ff 48 ff c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}