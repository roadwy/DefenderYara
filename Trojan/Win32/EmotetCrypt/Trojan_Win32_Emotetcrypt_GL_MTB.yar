
rule Trojan_Win32_Emotetcrypt_GL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 30 8d 4c 7d 00 2b ca 8a 0c 01 8b 44 24 28 8a 18 32 d9 8b 4c 24 38 88 18 8b 44 24 1c 40 3b c1 89 44 24 1c 0f 82 } //01 00 
		$a_81_1 = {68 61 31 6d 65 35 69 5e 74 62 62 49 37 72 32 37 64 63 6c 32 4d 5e 30 35 57 71 59 64 33 2a 34 76 6a 74 70 77 75 4e 65 58 } //00 00  ha1me5i^tbbI7r27dcl2M^05WqYd3*4vjtpwuNeX
	condition:
		any of ($a_*)
 
}