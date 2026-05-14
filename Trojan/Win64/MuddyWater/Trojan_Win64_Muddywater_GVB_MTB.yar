
rule Trojan_Win64_Muddywater_GVB_MTB{
	meta:
		description = "Trojan:Win64/Muddywater.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 5d e8 ff 15 77 ee 00 00 4c 8b c3 ba 08 00 00 00 48 8b c8 ff 15 56 ee 00 00 48 8b 4d d8 4c 8b c6 48 8b d8 48 8b d7 48 8d 45 e8 4c 8b cb 48 89 44 24 28 48 8b 45 e8 48 89 44 24 20 ff 15 be ea 02 00 85 c0 74 49 } //2
		$a_01_1 = {42 0f b6 04 01 ff c2 88 01 48 8d 49 01 48 63 c2 49 3b c1 72 eb } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}