
rule Trojan_MacOS_Amos_B_MTB{
	meta:
		description = "Trojan:MacOS/Amos.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_00_0 = {0a 69 69 38 eb 03 45 39 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 41 00 f1 41 ff ff 54 97 00 00 b0 f7 62 0e 91 e8 3e 40 39 09 1d 00 13 ea 02 40 f9 3f 01 00 71 55 b1 88 9a } //05 00 
		$a_00_1 = {0a 69 69 38 ab 03 59 38 4a 01 0b 4a 0a 69 29 38 29 05 00 91 3f 39 00 f1 41 ff ff 54 d6 00 00 d0 d6 a2 1e 91 d9 2f 8c 52 59 02 a0 72 c8 5e 40 39 09 1d 00 13 ca 06 40 f9 3f 01 00 71 54 b1 88 9a e0 03 13 aa } //00 00 
	condition:
		any of ($a_*)
 
}