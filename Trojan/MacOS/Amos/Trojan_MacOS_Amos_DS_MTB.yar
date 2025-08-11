
rule Trojan_MacOS_Amos_DS_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DS!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 e0 07 00 f9 00 00 00 d0 00 f4 15 91 86 00 00 94 } //1
		$a_01_1 = {e0 0b 40 f9 a8 43 5b b8 08 21 00 71 a8 43 1b b8 a8 83 5b b8 a9 43 5b b8 08 29 c9 1a 08 1d 00 12 e8 bf 00 39 e1 bf c0 39 6a 0a 00 94 01 00 00 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}