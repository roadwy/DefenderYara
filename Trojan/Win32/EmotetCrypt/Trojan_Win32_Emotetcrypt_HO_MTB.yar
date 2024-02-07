
rule Trojan_Win32_Emotetcrypt_HO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b c2 2b 05 90 01 04 2b 05 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b c2 2b 05 90 01 04 2b 05 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b c2 2b 05 90 01 04 2b 05 90 01 04 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 00 } //01 00 
		$a_81_1 = {79 39 74 53 75 62 26 6a 65 52 6b 5e 4f 49 21 39 5f 29 5a 5f 50 44 21 4a 5e 75 5a 64 26 21 6c 2a 58 78 29 51 7a 39 49 3f 6c 55 4b 3f 6b 38 6c 77 6c 4f 57 6c 51 77 44 4c 39 57 55 57 4a 3f 79 54 72 43 57 48 48 67 5a 58 3c 6a 77 34 51 4f 56 45 54 28 66 74 64 4f 32 41 7a 33 } //00 00  y9tSub&jeRk^OI!9_)Z_PD!J^uZd&!l*Xx)Qz9I?lUK?k8lwlOWlQwDL9WUWJ?yTrCWHHgZX<jw4QOVET(ftdO2Az3
	condition:
		any of ($a_*)
 
}