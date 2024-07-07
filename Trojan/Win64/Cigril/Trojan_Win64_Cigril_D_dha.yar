
rule Trojan_Win64_Cigril_D_dha{
	meta:
		description = "Trojan:Win64/Cigril.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 20 01 00 00 8d 42 f0 4d 8b f8 a9 e7 ff ff ff 0f 85 90 01 02 00 00 83 fa 28 0f 84 90 01 02 00 00 49 89 5b 08 8d 5a 03 c1 eb 02 90 00 } //1
		$a_01_1 = {48 83 ec 00 48 b8 00 00 00 00 00 00 00 00 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}