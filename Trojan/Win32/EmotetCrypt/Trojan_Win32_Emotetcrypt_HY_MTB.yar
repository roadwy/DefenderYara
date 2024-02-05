
rule Trojan_Win32_Emotetcrypt_HY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c8 2b 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 a1 90 01 04 0f af 05 90 01 04 2b c8 03 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 8b 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 00 } //01 00 
		$a_81_1 = {75 32 56 56 37 58 58 67 2a 3f 71 34 62 72 78 53 79 32 6a 4b 75 6f 29 6a 5e 55 55 74 46 57 3f 28 2a } //00 00 
	condition:
		any of ($a_*)
 
}