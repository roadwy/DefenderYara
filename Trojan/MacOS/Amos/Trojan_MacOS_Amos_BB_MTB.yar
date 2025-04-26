
rule Trojan_MacOS_Amos_BB_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 01 c7 46 88 2c 30 4c 39 e3 0f ?? ?? ?? ?? ?? 49 83 fe 08 0f ?? ?? ?? ?? ?? 48 89 ca 48 89 de 89 f7 44 29 e7 4c 89 e1 48 f7 d1 48 01 f1 48 83 e7 07 } //1
		$a_03_1 = {44 89 e9 c1 e1 05 48 89 c6 48 09 ce 41 83 fe 03 0f ?? ?? ?? ?? ?? 44 89 f1 83 c1 fd 41 89 f5 89 4d d4 41 d3 ed 49 8b 44 24 10 48 39 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}