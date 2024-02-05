
rule Trojan_Win32_Emotetcrypt_IK_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d1 8b 0d 90 01 04 0f af 0d 90 01 04 2b d1 03 15 90 01 04 8b 4d 08 0f b6 14 11 8b 4d 0c 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 8b 35 90 01 04 0f af 35 90 00 } //01 00 
		$a_81_1 = {61 52 3c 47 2b 4b 62 29 66 29 47 58 63 71 58 29 23 49 4f 61 34 4e 63 73 37 31 26 3e 51 36 3f 58 3e 64 49 38 39 40 42 42 3e 44 70 63 6b 26 24 3f 30 } //00 00 
	condition:
		any of ($a_*)
 
}