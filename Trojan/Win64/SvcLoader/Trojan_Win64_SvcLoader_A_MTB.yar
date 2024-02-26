
rule Trojan_Win64_SvcLoader_A_MTB{
	meta:
		description = "Trojan:Win64/SvcLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {45 33 f6 33 d2 8d 4a 0a ff 15 90 01 02 00 00 48 8b d8 48 85 c0 4c 8b 6d e8 90 00 } //02 00 
		$a_01_1 = {c7 45 f0 30 01 00 00 33 d2 41 b8 2c 01 00 00 48 8d 4d f4 e8 } //02 00 
		$a_01_2 = {48 8d 55 f0 48 8b cb ff 15 } //02 00 
		$a_03_3 = {48 8d 4d 1c ff 15 90 01 02 00 00 85 c0 90 00 } //02 00 
		$a_03_4 = {48 8d 55 f0 48 8b cb ff 15 90 01 02 00 00 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}