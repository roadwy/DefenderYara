
rule Trojan_BAT_AgentTesla_ABV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 7e 0f 00 00 95 2e 03 17 2b 01 16 58 7e 2d 00 00 04 17 9a 7e 2d 00 00 04 19 9a 20 7c 04 00 00 95 e0 95 7e 2d 00 00 04 19 9a 20 5f 09 00 00 95 61 7e 2d 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 06 00 "
		
	strings :
		$a_03_0 = {11 09 11 0e 8f 90 01 03 01 25 71 90 01 03 01 11 0c 11 0e 91 61 d2 81 90 01 03 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {47 65 74 44 72 69 76 65 73 } //01 00  GetDrives
		$a_01_4 = {24 35 66 32 37 65 39 32 61 2d 36 31 31 38 2d 34 62 63 37 2d 61 63 39 34 2d 33 35 34 62 32 37 66 31 65 38 30 66 } //00 00  $5f27e92a-6118-4bc7-ac94-354b27f1e80f
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABV_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 00 41 00 37 00 39 00 37 00 32 00 36 00 35 00 34 00 32 00 34 00 37 00 00 0d 36 00 31 00 36 00 31 00 36 00 31 00 00 29 70 00 61 00 6c 00 2e 00 45 00 76 00 65 00 6e 00 74 00 4c 00 6f 00 67 00 41 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {38 35 48 4e 71 48 49 65 51 64 52 5a 73 75 53 62 6b 77 2e 4b 6c 4e 6f 62 54 73 55 69 53 6b 58 57 37 57 58 48 39 } //01 00  85HNqHIeQdRZsuSbkw.KlNobTsUiSkXW7WXH9
		$a_01_4 = {24 30 32 62 65 64 66 62 39 2d 63 31 37 33 2d 34 32 33 61 2d 62 30 61 34 2d 64 65 66 35 36 36 38 62 62 64 34 64 } //01 00  $02bedfb9-c173-423a-b0a4-def5668bbd4d
		$a_01_5 = {59 00 61 00 59 00 62 00 59 00 63 00 59 00 64 00 59 00 65 00 59 00 66 00 59 00 67 00 59 00 68 00 59 00 6b 00 6a 00 6c 00 6a 00 6e 00 6d 00 6f 00 6d 00 70 00 6d 00 71 00 6d 00 72 00 6d 00 73 00 6d 00 74 00 6d 00 } //01 00  YaYbYcYdYeYfYgYhYkjljnmompmqmrmsmtm
		$a_01_6 = {4a 00 4f 00 4e 00 36 00 6e 00 5a 00 47 00 59 00 78 00 56 00 35 00 36 00 47 00 76 00 64 00 74 00 6f 00 36 00 2e 00 46 00 68 00 68 00 58 00 42 00 67 00 64 00 46 00 53 00 30 00 41 00 76 00 73 00 74 00 48 00 6a 00 33 00 63 00 } //00 00  JON6nZGYxV56Gvdto6.FhhXBgdFS0AvstHj3c
	condition:
		any of ($a_*)
 
}