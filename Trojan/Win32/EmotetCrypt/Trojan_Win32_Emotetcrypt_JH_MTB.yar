
rule Trojan_Win32_Emotetcrypt_JH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {e0 a5 a7 0f d7 03 11 a2 31 a4 33 b0 e8 ca 8d 53 f6 f1 91 01 7d f3 73 0a b4 b1 c8 0a f0 1b c8 cf d3 74 c5 2b 28 e7 55 58 2d 96 1e 00 5d 43 89 e6 df a5 26 b0 bd 4a c0 55 e7 e7 26 79 3d 4c 4e c8 } //01 00 
		$a_01_1 = {4d 61 63 72 6f 73 2e 64 6c 6c } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}