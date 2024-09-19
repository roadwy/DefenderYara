
rule Trojan_MacOS_Amos_AH_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AH!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 01 0b 6b a1 00 00 54 8a 00 00 b0 4a f1 43 79 2a 69 02 b9 1f 00 00 14 e9 2f 40 f9 6a 67 81 52 49 01 09 4b ea 2f 40 f9 eb 3f c1 39 29 7d 0a 1b ea 72 8a 52 2a 68 bd 72 29 29 0b 1b 8a 00 00 b0 } //1
		$a_00_1 = {ad 3d 10 53 bf c1 57 71 2d 02 00 54 2a 6d 1c 53 4a 01 09 4b 8a 29 08 39 ea 4b 40 b9 ec 4b 40 b9 4a 31 0e 1b ea 4b 00 b9 10 00 00 14 8a 00 00 b0 4a 99 44 79 aa 01 00 34 ea 43 40 b9 0a 01 00 34 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}