
rule Trojan_MacOS_Amos_FB_MTB{
	meta:
		description = "Trojan:MacOS/Amos.FB!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 83 cb 3d e0 93 8b 3d e8 0b 57 f9 e8 2b 17 f9 e8 0b 40 91 08 01 2e 91 1f 5d 0a 39 1f 01 0a 39 e9 5f 49 39 28 1d 00 13 ea 27 41 f9 1f 01 00 71 42 b1 89 9a 82 01 00 b4 e9 23 41 f9 1f 01 00 71 e8 03 09 91 35 b1 88 9a e0 03 15 aa e1 04 80 52 } //1
		$a_01_1 = {e8 5f 64 39 09 1d 00 13 ea 87 44 f9 3f 01 00 71 48 b1 88 9a e9 0b 40 91 29 01 3c 91 29 5d 45 39 2a 1d 00 13 eb 27 58 f9 5f 01 00 71 69 b1 89 9a e9 03 29 aa e0 0f 40 91 00 80 3b 91 e1 03 24 91 a2 06 00 91 03 01 09 8b e4 83 0c 91 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}