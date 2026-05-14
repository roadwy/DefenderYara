
rule Trojan_Win64_Dapato_SX_MTB{
	meta:
		description = "Trojan:Win64/Dapato.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 ?? 0f be c0 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c5 4d 03 cd 41 83 f8 } //10
		$a_03_1 = {41 f7 e0 c1 ea ?? 0f be c2 6b c8 ?? 41 8a c0 2a c1 04 ?? 41 30 01 45 03 c4 4d 03 cc 41 83 f8 } //10
		$a_03_2 = {48 33 d8 48 89 5d ?? 48 c7 01 00 00 00 00 33 c9 48 8d 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 74 2e } //50
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*50) >=60
 
}