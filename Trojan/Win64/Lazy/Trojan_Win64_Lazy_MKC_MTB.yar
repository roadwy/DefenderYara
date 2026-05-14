
rule Trojan_Win64_Lazy_MKC_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 05 d1 87 01 00 48 89 87 b8 00 00 00 48 8b 05 c3 87 01 00 48 89 44 24 30 f0 83 00 01 48 8b 5c 24 30 b9 0d } //15
		$a_01_1 = {c7 81 c8 00 00 00 01 00 00 00 c6 81 74 01 00 00 43 c6 81 f7 01 00 00 43 48 8d 05 24 7a 01 00 48 89 81 b8 00 00 00 b9 0d } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}
rule Trojan_Win64_Lazy_MKC_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 5c 77 2d 5d 7b 32 34 2c 32 37 7d 5c 2e 5b 5c 77 2d 5d 7b 36 2c 37 7d 5c 2e 5b 5c 77 2d 5d 7b 32 35 2c 31 31 30 7d } //15 [\w-]{24,27}\.[\w-]{6,7}\.[\w-]{25,110}
		$a_01_1 = {64 51 77 34 77 39 57 67 58 63 51 3a } //10 dQw4w9WgXcQ:
		$a_01_2 = {64 69 73 63 6f 72 64 62 61 63 6b 75 70 79 65 64 65 6b } //5 discordbackupyedek
		$a_01_3 = {2e 52 4f 42 4c 4f 53 45 43 55 52 49 54 59 3d } //3 .ROBLOSECURITY=
		$a_01_4 = {57 41 52 4e 49 4e 47 3a 2d 44 4f 2d 4e 4f 54 2d 53 48 41 52 45 2d 54 48 49 53 } //2 WARNING:-DO-NOT-SHARE-THIS
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}