
rule Trojan_Win64_InjectorCrypt_SO_MTB{
	meta:
		description = "Trojan:Win64/InjectorCrypt.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 01 c3 48 90 0a 35 00 8b 05 90 01 02 00 00 35 90 01 04 89 41 04 8b 05 90 01 02 00 00 35 90 00 } //01 00 
		$a_02_1 = {48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 55 41 56 48 81 ec d0 00 00 00 4c 8b 15 90 01 04 49 8b e9 4d 8b e0 4d 8b 9a 90 01 04 44 8b ea 4c 8b f1 4d 85 db 0f 84 90 01 04 48 8d 4c 24 50 e8 90 01 04 48 90 01 04 e8 90 01 04 41 8b 92 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}