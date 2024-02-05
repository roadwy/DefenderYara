
rule Trojan_BAT_Zilla_KAD_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {39 00 66 00 34 00 64 00 65 00 6a 00 2f 00 2f 00 2f 00 66 00 2f 00 2f 00 57 00 } //0a 00 
		$a_01_1 = {20 31 97 f4 ff 13 14 20 13 eb ff ff 13 14 20 34 b0 ff ff 13 14 20 ed 41 06 00 13 15 20 be b0 00 00 13 15 20 4e 6e 08 00 13 16 20 c5 50 02 00 13 16 20 19 51 02 00 13 16 20 0e 21 fa ff 13 17 20 26 a9 00 00 13 17 20 e9 37 ff ff 13 17 20 8b 71 03 00 13 18 20 d7 21 01 00 13 18 16 13 19 16 13 19 20 ea 5a 02 00 13 1a 20 d8 e8 00 00 13 1a 20 0d 5f 02 00 13 1a 20 14 06 02 00 13 1a 20 ab 47 f8 ff 13 1b } //00 00 
	condition:
		any of ($a_*)
 
}