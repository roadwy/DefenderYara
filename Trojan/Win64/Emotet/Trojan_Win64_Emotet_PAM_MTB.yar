
rule Trojan_Win64_Emotet_PAM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 c1 fa 90 01 01 c1 ea 90 01 01 01 d0 83 e0 90 01 01 29 d0 48 98 4c 01 c8 0f b6 00 44 31 c0 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Emotet_PAM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb c1 fa 90 01 01 8b c2 c1 e8 1f 03 d0 8b c3 ff c3 8d 0c 90 01 01 c1 e1 90 01 01 2b c1 48 63 c8 42 8a 04 19 43 32 04 01 41 88 00 49 ff c0 48 83 ef 01 74 90 00 } //1
		$a_03_1 = {41 f7 ea c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 48 98 48 8d 14 80 49 63 c2 41 83 c2 90 01 01 48 03 c8 0f b6 04 d1 43 32 44 08 ff 48 83 ee 90 01 01 41 88 41 ff 74 09 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}