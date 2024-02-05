
rule Trojan_Win32_Emotetcrypt_GF_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 03 15 90 01 04 03 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 03 15 90 01 04 03 c2 8b 15 90 01 04 0f af 15 90 01 04 03 c2 2b 05 90 01 04 2b 05 90 01 04 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 90 00 } //01 00 
		$a_81_1 = {40 44 24 5a 24 47 4a 25 74 34 6b 4e 4f 71 52 25 50 44 59 6c 43 2b 37 53 30 4b 39 79 23 63 43 54 70 29 41 74 3c 44 77 55 61 74 50 43 24 23 38 54 6b 39 2a 43 75 58 75 64 33 34 64 3f 69 71 4b 66 78 4c 72 34 71 63 31 71 6f 3c } //00 00 
	condition:
		any of ($a_*)
 
}