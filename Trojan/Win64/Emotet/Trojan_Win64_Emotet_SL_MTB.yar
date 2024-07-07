
rule Trojan_Win64_Emotet_SL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d7 33 c9 ff 15 0d b2 07 00 8b cf b8 31 0c c3 30 f7 ef ff c7 c1 fa 02 8b c2 c1 e8 1f 03 d0 6b c2 15 2b c8 48 63 c1 48 8d 0d 81 86 0b 00 8a 04 08 42 32 04 36 41 88 06 49 ff c6 3b fd 72 c1 48 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}