
rule Spammer_Win32_Fbphotofake_A{
	meta:
		description = "Spammer:Win32/Fbphotofake.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 6d 61 69 6c 3d 25 73 26 70 61 73 73 3d 25 73 26 6c 6f 67 69 6e 3d 4c 6f 67 25 32 30 49 6e } //01 00  email=%s&pass=%s&login=Log%20In
		$a_00_1 = {2e 5c 70 69 70 65 5c 66 61 63 65 62 6f 6f 6b } //01 00  .\pipe\facebook
		$a_00_2 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 4e 65 74 77 6f 72 6b 20 69 6e 69 74 69 61 6c 69 7a 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 21 21 } //01 00  [FACEBOOK] Network initialized successfully!!!
		$a_00_3 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 54 72 79 69 6e 67 20 74 6f 20 6c 6f 67 69 6e 20 77 69 74 68 20 25 73 } //01 00  [FACEBOOK] Trying to login with %s
		$a_00_4 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 53 70 61 6d 20 74 68 72 65 61 64 20 73 74 61 72 74 65 64 2e } //01 00  [FACEBOOK] Spam thread started.
		$a_00_5 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 57 72 69 74 74 65 6e 2c 20 73 74 61 72 74 69 6e 67 20 73 70 61 6d 2e 2e 2e } //01 00  [FACEBOOK] Written, starting spam...
		$a_00_6 = {5b 46 41 43 45 42 4f 4f 4b 5d 20 53 74 61 72 74 20 73 65 6e 64 69 6e 67 20 25 64 20 50 4f 53 54 20 64 61 74 61 21 } //01 00  [FACEBOOK] Start sending %d POST data!
		$a_01_7 = {25 73 3f 61 63 74 3d 66 62 5f 73 74 61 74 26 6e 75 6d 3d 25 64 } //00 00  %s?act=fb_stat&num=%d
	condition:
		any of ($a_*)
 
}