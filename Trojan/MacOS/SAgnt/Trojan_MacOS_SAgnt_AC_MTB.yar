
rule Trojan_MacOS_SAgnt_AC_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.AC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 56 53 50 48 c7 04 24 00 00 00 00 48 83 fe 09 b8 08 00 00 00 48 0f 43 c6 48 89 e1 48 89 fa 48 89 cf 48 89 c6 48 89 d3 e8 59 90 25 00 89 c1 31 c0 85 c9 75 17 4c 8b 34 24 4d 85 f6 74 0e 4c 89 f7 48 89 de e8 45 8e 25 00 4c 89 f0 } //1
		$a_01_1 = {48 85 db 0f 88 43 01 00 00 49 89 f4 0f b6 05 7b 7d 3b 00 be 01 00 00 00 48 89 df e8 36 fe ff ff 48 85 c0 0f 84 28 01 00 00 49 89 c7 48 89 c7 4c 89 e6 48 89 da e8 36 8f 25 00 49 83 3e 00 74 09 49 8b 7e 08 e8 97 8e 25 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}