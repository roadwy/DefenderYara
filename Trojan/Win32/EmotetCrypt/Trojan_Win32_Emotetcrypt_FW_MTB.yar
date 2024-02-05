
rule Trojan_Win32_Emotetcrypt_FW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d1 2b 15 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 2b d1 2b 15 90 01 04 03 15 90 01 04 03 15 90 01 04 8b 4d 90 01 01 0f b6 14 11 8b 4d 90 01 01 0f b6 04 01 33 c2 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 75 90 01 01 2b f2 90 00 } //01 00 
		$a_81_1 = {6b 46 47 4a 5e 6a 38 39 77 73 2a 45 59 78 71 46 56 30 2b 36 54 76 5f 4b 6f 51 4b 4b 5e 69 56 50 6b 53 4d 77 63 43 6d 76 65 4e 74 41 49 3f 26 49 2b 36 31 39 37 75 38 52 5f 65 42 6c 77 4f 33 69 71 66 6d 40 34 21 67 71 63 58 2b 24 5e } //00 00 
	condition:
		any of ($a_*)
 
}