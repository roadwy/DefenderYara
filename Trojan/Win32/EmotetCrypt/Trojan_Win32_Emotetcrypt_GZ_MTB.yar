
rule Trojan_Win32_Emotetcrypt_GZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 0f af c3 8b 1d 90 01 04 0f af c7 03 e8 a1 90 01 04 03 d1 0f af d8 8d 0c 36 be 90 01 04 2b f1 0f af f0 8d 44 7e 90 01 01 0f af 05 90 01 04 03 eb 2b 2d 90 01 04 8d 0c 6a 8a 14 08 8b 44 24 90 01 01 8a 18 8b 4c 24 90 01 01 32 da 88 18 90 00 } //01 00 
		$a_81_1 = {65 3e 7a 54 23 59 79 4c 49 71 38 23 30 44 58 49 63 58 37 68 65 4f 51 47 3c 48 40 2b 43 21 47 6c 5e 53 49 4d 61 70 64 6b 39 40 6f 74 68 4d 29 6a 44 5e 48 4a 5e 6f 67 4e 47 65 57 25 77 26 49 7a 21 47 37 47 57 66 5e 78 31 74 3c 4b 5a 6d 69 68 55 34 39 62 4d 79 39 74 49 4c 77 62 44 5f 55 3c 7a 49 78 32 45 43 51 4e 29 79 38 52 43 46 57 4e 64 } //00 00  e>zT#YyLIq8#0DXIcX7heOQG<H@+C!Gl^SIMapdk9@othM)jD^HJ^ogNGeW%w&Iz!G7GWf^x1t<KZmihU49bMy9tILwbD_U<zIx2ECQN)y8RCFWNd
	condition:
		any of ($a_*)
 
}