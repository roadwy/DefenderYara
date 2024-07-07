
rule Trojan_Linux_Tsunami_B_xp{
	meta:
		description = "Trojan:Linux/Tsunami.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 51 52 49 51 52 4c 51 52 4c 51 52 41 51 52 4c 51 52 4c } //1 KQRIQRLQRLQRAQRLQRL
		$a_01_1 = {66 51 52 61 51 52 6b 51 52 65 51 52 6e 51 52 61 51 52 6d 51 52 65 } //1 fQRaQRkQReQRnQRaQRmQRe
		$a_01_2 = {47 51 52 45 51 52 54 51 52 53 51 52 50 51 52 4f 51 52 4f 51 52 46 51 52 53 } //1 GQREQRTQRSQRPQROQROQRFQRS
		$a_01_3 = {51 52 42 51 52 4f 51 52 54 51 52 53 } //1 QRBQROQRTQRS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}