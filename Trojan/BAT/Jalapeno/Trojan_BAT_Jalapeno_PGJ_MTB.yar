
rule Trojan_BAT_Jalapeno_PGJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 02 7b 05 00 00 04 08 9a 7d 06 00 00 04 02 03 28 ?? 00 00 06 0d 02 7b 09 00 00 04 09 72 01 00 00 70 6f ?? 00 00 0a 0b 07 72 01 00 00 70 28 ?? 00 00 0a 2c 07 07 28 ?? 00 00 2b 2a 08 17 58 0c 08 02 7b 05 00 00 04 8e 69 32 b5 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_BAT_Jalapeno_PGJ_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 00 12 01 28 ?? 00 00 06 02 06 07 28 ?? 00 00 06 51 28 ?? 00 00 06 0c 03 08 28 ?? 00 00 06 51 2a } //4
		$a_80_1 = {6a 59 44 34 71 54 37 39 69 6a 57 62 63 50 6f 6b 78 6c 58 37 6b 69 48 64 7a 72 2b 6d 71 54 64 50 74 41 4f 52 6b 51 65 30 34 4d 52 6c 76 4d 46 52 30 59 55 67 49 37 51 44 6b 5a 45 48 74 4f 44 45 } //jYD4qT79ijWbcPokxlX7kiHdzr+mqTdPtAORkQe04MRlvMFR0YUgI7QDkZEHtODE  1
	condition:
		((#a_03_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}
rule Trojan_BAT_Jalapeno_PGJ_MTB_3{
	meta:
		description = "Trojan:BAT/Jalapeno.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 69 00 72 00 6f 00 73 00 61 00 76 00 76 00 61 00 2d 00 63 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f } //1
		$a_01_1 = {63 6d 56 6d 5a 58 4a 79 5a 58 49 39 5a 6e 4a 6c 5a 53 31 6b 62 33 64 75 62 47 39 68 5a 43 5a 6e 59 57 52 66 63 32 39 31 63 6d 4e 6c 50 54 45 6d 5a 32 4e 73 61 57 51 39 52 55 46 4a 59 55 6c 52 62 32 4a 44 61 45 31 4a 4e 33 46 36 56 47 38 35 58 30 31 70 64 30 31 57 55 46 56 4d 58 30 46 53 4d 57 64 79 51 57 4e 54 52 55 46 42 57 55 46 54 51 55 46 46 5a 30 78 48 54 47 5a 45 58 30 4a 33 52 51 3d 3d } //4 cmVmZXJyZXI9ZnJlZS1kb3dubG9hZCZnYWRfc291cmNlPTEmZ2NsaWQ9RUFJYUlRb2JDaE1JN3F6VG85X01pd01WUFVMX0FSMWdyQWNTRUFBWUFTQUFFZ0xHTGZEX0J3RQ==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}