
rule Trojan_Win64_Scar_GMK_MTB{
	meta:
		description = "Trojan:Win64/Scar.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {4c 89 f1 4c 89 4c 24 58 e8 90 01 04 31 d2 41 ba 3e 00 00 00 44 89 f9 89 c0 41 ff c7 4c 8b 4c 24 58 49 f7 f2 44 39 7c 24 48 66 0f be 44 15 00 66 41 89 04 4c 90 00 } //01 00 
		$a_80_1 = {47 6c 6f 62 61 6c 5c 4d 25 6c 6c 75 } //Global\M%llu  00 00 
	condition:
		any of ($a_*)
 
}