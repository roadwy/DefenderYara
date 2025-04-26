
rule Trojan_MacOS_Amos_AY_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AY!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 45 b8 88 0c 08 48 89 c8 31 d2 49 f7 f5 49 8b 04 24 8a 04 10 48 8b 55 88 88 04 0a 48 ff c1 48 81 f9 00 01 00 00 75 ?? 31 c0 31 c9 4c 8b bd 78 ff ff ff } //1
		$a_01_1 = {0f 57 c0 4c 8b 75 c8 41 0f 11 06 49 c7 46 10 00 00 00 00 45 31 ff 4c 8d 2d ff 8c 00 00 31 db 45 31 e4 31 c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}