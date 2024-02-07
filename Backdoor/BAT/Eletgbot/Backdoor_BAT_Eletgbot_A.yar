
rule Backdoor_BAT_Eletgbot_A{
	meta:
		description = "Backdoor:BAT/Eletgbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 32 4d 67 64 47 6c 74 5a 57 39 31 64 43 42 37 4d 48 30 3d } //01 00  L2MgdGltZW91dCB7MH0=
		$a_01_1 = {55 47 39 33 5a 58 4a 7a 61 47 56 73 62 41 3d 3d } //01 00  UG93ZXJzaGVsbA==
		$a_01_2 = {51 00 57 00 31 00 7a 00 61 00 56 00 4e 00 6a 00 59 00 57 00 35 00 43 00 64 00 57 00 5a 00 6d 00 5a 00 58 00 49 00 3d 00 } //01 00  QW1zaVNjYW5CdWZmZXI=
		$a_01_3 = {59 00 57 00 31 00 7a 00 61 00 53 00 35 00 6b 00 62 00 47 00 77 00 3d 00 } //01 00  YW1zaS5kbGw=
		$a_00_4 = {54 65 6c 65 67 72 61 6d 54 6f 6b 65 6e } //01 00  TelegramToken
		$a_01_5 = {56 58 56 70 5a 45 5a 79 62 32 31 54 64 48 4a 70 62 6d 64 42 } //01 00  VXVpZEZyb21TdHJpbmdB
		$a_01_6 = {44 51 6f 7a 37 37 69 50 34 6f 4f 6a 49 45 5a 70 62 47 55 67 50 53 41 3d 28 61 48 52 30 63 48 4d 36 4c 79 39 68 63 47 6b 75 64 47 56 73 5a 57 64 79 59 57 30 75 62 33 4a 6e 4c 32 4a 76 64 41 3d 3d } //00 00  DQoz77iP4oOjIEZpbGUgPSA=(aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdA==
	condition:
		any of ($a_*)
 
}