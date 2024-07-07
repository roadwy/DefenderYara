
rule Trojan_Win64_Lazy_NLA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 0d 75 31 1e 00 48 8b 01 48 05 90 01 04 48 89 41 10 48 89 41 90 01 01 e8 7f 43 00 00 48 8d 3d 90 01 04 e8 f3 41 00 00 48 8b 1d 24 66 23 00 90 00 } //5
		$a_01_1 = {4e 5a 52 42 2e 78 } //1 NZRB.x
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_Lazy_NLA_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8d 50 02 33 c9 48 8b 03 ff 15 90 01 04 e8 13 07 00 00 48 8b d8 48 83 38 00 74 14 90 00 } //5
		$a_03_1 = {48 8d 4c 24 20 e8 1e e6 ff ff 48 8d 15 5f 9a 04 00 48 8d 4c 24 90 01 01 e8 dd 1e 00 00 cc 33 c0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}