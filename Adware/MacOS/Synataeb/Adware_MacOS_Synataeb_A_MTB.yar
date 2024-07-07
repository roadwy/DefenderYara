
rule Adware_MacOS_Synataeb_A_MTB{
	meta:
		description = "Adware:MacOS/Synataeb.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 8b 7d c8 48 09 01 48 8b 5d c0 48 8b 43 30 4c 89 e9 48 c1 e1 04 4c 89 34 08 4c 89 64 08 08 49 c1 e5 05 4c 03 6b 38 4c 8d b5 50 ff ff ff 4c 89 f7 4c 89 ee e8 b5 00 00 00 4c 89 f7 } //1
		$a_00_1 = {49 89 df e8 b7 0a 00 00 49 89 c5 8a 4b 20 48 c7 c3 ff ff ff ff 48 d3 e3 48 f7 d3 49 21 dd 4c 89 ea 48 c1 ea 06 49 8b 74 d7 40 b8 01 00 00 00 44 89 e9 48 d3 e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}