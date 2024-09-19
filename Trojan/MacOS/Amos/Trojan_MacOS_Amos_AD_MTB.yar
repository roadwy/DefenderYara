
rule Trojan_MacOS_Amos_AD_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AD!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 6b 00 b9 28 00 80 52 29 6b 68 38 ea a3 41 39 29 01 0a 4a 29 6b 28 38 08 05 00 91 1f 11 00 f1 41 ?? ?? ?? e0 43 01 91 e1 13 40 f9 } //1
		$a_01_1 = {f8 5f bc a9 f6 57 01 a9 f4 4f 02 a9 fd 7b 03 a9 fd c3 00 91 f7 03 02 aa f6 03 01 aa f4 03 00 aa 13 80 06 91 15 20 00 91 88 00 00 d0 08 e1 04 91 09 61 00 91 09 00 00 f9 08 01 01 91 08 d0 00 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}