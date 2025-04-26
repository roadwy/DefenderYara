
rule Trojan_MacOS_Amos_K_MTB{
	meta:
		description = "Trojan:MacOS/Amos.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 83 01 d1 fa 67 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 f3 03 08 aa 1f 7d 00 a9 1f 09 00 f9 08 5c 40 39 09 1d 00 13 0a 2c 40 a9 3f 01 00 71 56 b1 80 9a 68 b1 88 9a e8 0a 00 b4 } //1
		$a_00_1 = {15 00 80 d2 e8 37 40 39 09 7d 02 53 e9 27 00 39 e9 3b 40 39 2a 7d 04 53 0a 05 1c 33 ea 2b 00 39 e8 3f 40 39 0a 7d 06 53 2a 0d 1e 33 ea 2f 00 39 08 15 00 12 e8 33 00 39 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}