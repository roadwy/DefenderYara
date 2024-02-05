
rule Trojan_Win32_Emotetcrypt_HS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 4a 5f 39 49 48 2b 34 6d 6c 6c 47 62 33 25 6a 42 57 24 6b 25 61 31 35 73 45 3c 78 75 35 52 40 4b 38 44 21 6c 74 79 72 48 6d 6e 36 51 47 70 3f 5a 65 6c 4d 4a 30 69 74 4a 6c 59 4d 65 46 45 4e 67 23 74 67 5f 4e 72 46 45 69 30 57 6b 46 7a 63 52 31 6a 37 72 77 2b 3e 61 21 64 24 66 69 6d 23 7a 4d 46 51 34 71 51 6f 24 77 63 62 49 53 74 } //01 00 
		$a_81_1 = {7a 7a 71 79 5f 30 51 79 6c 35 65 61 3e 78 68 38 6a 54 5f 6a 72 6d 37 35 48 5e 26 46 65 23 56 6a 74 28 44 38 58 4f 6d 46 63 6e 61 73 6a 35 43 58 75 } //00 00 
	condition:
		any of ($a_*)
 
}