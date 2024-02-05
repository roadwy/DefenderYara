
rule Trojan_Win64_Emotetcrypt_PC_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 5e 25 52 35 24 24 3f 74 2a 64 52 30 52 5f 29 72 } //01 00 
		$a_03_1 = {48 8b 8c 24 90 01 04 0f b6 04 01 8b 8c 24 90 01 04 33 c8 8b c1 8b 0d 90 01 04 8b 94 24 90 01 04 03 d1 8b ca 90 00 } //01 00 
		$a_03_2 = {ff c0 89 84 24 90 01 04 48 63 84 24 90 01 04 48 3b 84 24 90 01 04 0f 83 90 01 04 48 63 84 24 90 01 04 48 8b 8c 24 90 01 04 0f b6 04 01 89 84 24 90 01 04 8b 84 24 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}