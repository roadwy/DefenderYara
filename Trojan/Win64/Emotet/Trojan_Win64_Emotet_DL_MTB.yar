
rule Trojan_Win64_Emotet_DL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 99 41 f7 fa 48 8b 05 90 02 04 48 63 d2 44 8a 04 10 45 32 04 0b 45 88 04 09 48 ff c1 48 81 f9 9d 0b 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_DL_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 ff c1 41 f7 e0 41 8b c0 41 ff c0 c1 ea 05 6b d2 29 2b c2 48 63 c8 42 0f b6 04 11 42 32 44 0e ff 41 88 41 ff 44 3b c5 72 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}