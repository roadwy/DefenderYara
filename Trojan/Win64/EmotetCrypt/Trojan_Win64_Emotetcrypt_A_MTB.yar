
rule Trojan_Win64_Emotetcrypt_A_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 72 65 69 73 6d 65 6f 57 } //01 00 
		$a_81_1 = {65 70 6e 65 63 67 67 7a 67 6c 6b 70 69 6c 61 6d } //01 00 
		$a_81_2 = {66 79 71 7a 78 75 76 66 67 77 6a 77 79 75 6b } //01 00 
		$a_01_3 = {4c 63 c6 4d 8d 49 01 49 8b c3 ff c6 49 f7 e0 48 d1 ea 48 6b ca 0b 4c 2b c1 42 0f b6 4c 84 50 41 30 49 ff 81 fe 00 ca 02 00 } //00 00 
	condition:
		any of ($a_*)
 
}