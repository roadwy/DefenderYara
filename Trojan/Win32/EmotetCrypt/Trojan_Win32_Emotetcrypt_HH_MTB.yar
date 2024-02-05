
rule Trojan_Win32_Emotetcrypt_HH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 2b 05 90 01 04 03 05 90 01 04 2b 05 90 01 04 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 8b 3d 90 01 04 0f af 3d 90 01 04 8b 1d 90 01 04 0f af 1d 90 01 04 89 55 e8 90 00 } //01 00 
		$a_81_1 = {38 32 79 40 6b 6f 73 3c 65 39 62 3f 24 23 55 66 55 53 54 46 45 64 70 75 47 76 40 4b 38 25 75 4b 28 31 24 62 37 4f 74 4d 2b 25 36 4b 35 62 3e 6a } //00 00 
	condition:
		any of ($a_*)
 
}