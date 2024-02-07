
rule Trojan_Win32_ClipBanker_RL_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 39 4e 7a 63 68 56 68 51 56 38 64 4a 34 4e 34 45 71 37 48 45 58 47 39 66 66 38 71 43 6f 4c 62 76 45 } //01 00  19NzchVhQV8dJ4N4Eq7HEXG9ff8qCoLbvE
		$a_01_1 = {74 7a 31 55 6b 34 78 69 7a 53 42 44 77 66 62 72 36 57 35 44 4d 56 64 32 33 72 79 47 51 6d 64 5a 66 6b 56 48 } //01 00  tz1Uk4xizSBDwfbr6W5DMVd23ryGQmdZfkVH
		$a_01_2 = {30 78 66 39 63 36 66 38 34 39 30 31 31 42 44 33 33 41 44 39 35 30 34 37 45 65 66 62 39 32 30 65 65 39 42 37 31 30 32 31 34 61 } //01 00  0xf9c6f849011BD33AD95047Eefb920ee9B710214a
		$a_01_3 = {62 6e 62 31 66 67 61 30 7a 70 63 77 73 76 77 76 33 32 72 78 36 6b 7a 74 38 67 6d 75 6b 77 72 63 6a 6d 33 36 63 6a 73 61 76 6d } //01 00  bnb1fga0zpcwsvwv32rx6kzt8gmukwrcjm36cjsavm
		$a_01_4 = {62 69 74 63 6f 69 6e 63 61 73 68 3a } //01 00  bitcoincash:
		$a_01_5 = {62 63 68 72 65 67 3a } //00 00  bchreg:
	condition:
		any of ($a_*)
 
}