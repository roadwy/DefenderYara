
rule Trojan_MacOS_Amos_AL_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AL!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 00 aa e3 ff ff 97 e0 03 13 aa b9 05 00 94 fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6 } //1
		$a_03_1 = {e0 03 13 aa c8 00 00 94 f4 03 00 aa e0 03 13 aa 06 01 00 94 9f 02 00 eb 82 ?? ?? ?? 80 02 c0 39 04 01 00 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}