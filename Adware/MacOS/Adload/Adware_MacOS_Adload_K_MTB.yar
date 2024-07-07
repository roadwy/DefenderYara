
rule Adware_MacOS_Adload_K_MTB{
	meta:
		description = "Adware:MacOS/Adload.K!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 8b 68 04 48 89 df e8 90 01 03 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 90 00 } //1
		$a_03_1 = {48 8d bd 10 ff ff ff e8 90 01 04 48 8b 9d 80 fe ff ff 48 85 db 74 23 48 c7 c0 ff ff ff ff f0 48 0f c1 43 08 48 85 c0 75 90 01 01 48 8b 03 90 00 } //1
		$a_00_2 = {6b 65 79 65 6e 75 6d 65 72 61 74 6f 72 } //1 keyenumerator
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}