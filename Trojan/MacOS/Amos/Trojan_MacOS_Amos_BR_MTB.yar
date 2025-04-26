
rule Trojan_MacOS_Amos_BR_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BR!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 09 c8 f3 0f 5e c1 66 0f 3a 0a c0 0a f3 48 0f 2c c8 48 89 ca 48 c1 fa 3f f3 0f 5c 05 8b 0d 00 00 f3 48 0f 2c f8 48 21 d7 48 09 cf 48 39 f8 48 0f 47 f8 41 bd 02 00 00 00 48 83 ff 01 74 ?? 48 8d 47 ff 48 85 c7 75 18 } //1
		$a_03_1 = {41 be 08 00 00 00 49 29 d6 85 d2 74 ?? 83 fa 08 74 ?? b9 40 00 00 00 48 29 d1 4c 39 f1 4c 89 f6 48 0f 42 f1 29 f1 48 c7 c7 ff ff ff ff 48 d3 ef 89 d1 48 d3 ef 48 d3 e7 48 f7 d7 48 21 f8 48 89 03 49 29 f6 48 83 c3 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}