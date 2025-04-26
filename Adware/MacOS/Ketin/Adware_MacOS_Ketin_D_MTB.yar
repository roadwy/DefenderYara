
rule Adware_MacOS_Ketin_D_MTB{
	meta:
		description = "Adware:MacOS/Ketin.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fd 03 1d aa e0 17 40 f9 76 ?? ?? ?? a8 83 5e f8 69 00 00 ?? 29 41 1b 91 21 01 40 f9 e9 1b 40 f9 e0 13 00 f9 e0 03 09 aa e2 13 40 f9 ea 03 00 91 48 01 00 f9 5c ?? ?? ?? e0 0f 00 f9 } //1
		$a_03_1 = {08 01 40 f9 aa 83 5e f8 1f 01 0a eb e9 0f 00 b9 c1 ?? ?? ?? e8 0f 40 b9 08 01 00 12 00 1d 00 12 ff c3 11 91 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6 a0 03 02 d1 08 00 80 d2 e1 03 08 aa } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}