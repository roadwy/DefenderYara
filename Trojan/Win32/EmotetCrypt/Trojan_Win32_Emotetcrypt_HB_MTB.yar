
rule Trojan_Win32_Emotetcrypt_HB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af ce 0f af ce 03 d3 bb 90 01 04 2b d9 8d 4e 01 0f af de 0f af c8 a1 90 01 04 2b c8 2b ce c1 e1 02 2b c8 83 e9 05 0f af cf 03 c8 03 d3 03 ca 8b 15 90 01 04 8d 04 91 8a 0c 28 8b 44 24 20 8a 18 32 d9 8b 4c 24 30 88 18 90 00 } //01 00 
		$a_81_1 = {67 32 52 63 55 2a 5e 76 78 4b 29 65 35 2b 34 5e 73 65 73 41 72 4c 67 28 30 55 44 58 34 50 79 57 50 79 28 45 51 38 56 74 4a 6b 61 34 3c 39 5a 55 24 3e 48 49 25 35 34 3f 40 54 66 2b 42 62 46 5f 29 59 57 2a 21 73 56 4d 76 4d 34 79 61 25 37 62 43 47 6b 71 42 67 48 4d 26 37 49 72 3f 49 2a 34 59 75 63 4d 52 } //00 00 
	condition:
		any of ($a_*)
 
}