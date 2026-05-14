
rule Trojan_Win64_Scrop_NP_MTB{
	meta:
		description = "Trojan:Win64/Scrop.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 c2 48 8d 45 b0 48 01 d0 66 c7 00 5c 00 8b 85 18 06 00 00 48 98 48 8b 94 c5 d0 04 00 00 48 8d 45 b0 48 89 c1 } //2
		$a_01_1 = {48 83 bd b8 08 00 00 00 74 2a 8b 85 b4 08 00 00 48 63 d0 48 8b 8d b8 08 00 00 48 8d 85 b0 00 00 00 49 89 c9 49 89 d0 ba 01 00 00 00 48 89 c1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}