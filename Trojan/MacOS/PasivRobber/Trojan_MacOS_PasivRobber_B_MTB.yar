
rule Trojan_MacOS_PasivRobber_B_MTB{
	meta:
		description = "Trojan:MacOS/PasivRobber.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e2 0d 7f 29 e4 15 c2 28 42 08 c0 5a 63 08 c0 5a 84 08 c0 5a a5 08 c0 5a 5f fc 1f 71 e6 97 9f 1a 5f 00 20 71 e7 27 9f 1a 7f fc 1f 71 f4 97 9f 1a 7f 00 20 71 f7 27 9f 1a 9f fc 1f 71 f8 97 9f 1a 9f 00 20 71 f9 27 9f 1a bf fc 1f 71 fc 97 9f 1a bf 00 20 71 fe 27 9f 1a a5 00 02 71 09 26 9f 9a 84 00 02 71 0a 26 9f 9a 63 00 02 71 1b 26 9f 9a 42 00 02 71 42 7c 07 53 13 26 9f 9a 5f fc 07 71 62 7c 07 53 e3 27 9f 1a 5f fc 07 71 82 7c 07 53 e4 27 9f 1a 5f fc 07 71 } //1
		$a_01_1 = {4d e1 5f 38 ae fd 42 d3 8e 69 6e 38 6f 01 08 8b ee f1 1f 38 ad 6d 1c 53 ad 05 7c 92 4e f1 5f 38 ad 11 4e aa 8d 69 6d 38 ed 01 00 39 cd 75 1e 53 ad 0d 7e 92 4e 35 40 38 ad 19 4e aa 8d 69 6d 38 ed 05 00 39 cd 15 40 92 8d 69 6d 38 ed 09 00 39 08 11 00 91 3f 01 08 eb } //1
		$a_01_2 = {fc 57 00 a9 f3 53 03 29 f7 13 00 f9 0d 00 80 d2 0e 00 80 d2 0c 00 80 d2 0b 00 80 d2 08 fd 42 d3 08 05 00 91 f5 03 08 aa 09 f1 7e 92 c8 0a 09 8b f6 0b 00 f9 cf 22 00 91 f6 03 09 aa 90 00 80 52 51 00 80 52 60 00 80 52 e1 03 09 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}