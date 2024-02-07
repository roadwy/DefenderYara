
rule Trojan_Win64_Shelm_MB_MTB{
	meta:
		description = "Trojan:Win64/Shelm.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 86 49 eb 67 31 5d f2 69 1a 5c 3c b9 1b e0 1e 18 53 97 88 55 90 fa 8d 37 cc 99 50 9a 46 a6 74 } //05 00 
		$a_01_1 = {a1 23 f2 e2 e7 d5 42 0d b9 40 bf ab 85 2b 97 42 e7 33 cf 70 3b df 39 f2 7e c5 86 54 f1 e6 9c 65 } //01 00 
		$a_01_2 = {2e 74 6c 73 } //01 00  .tls
		$a_01_3 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //01 00  GetStartupInfoA
		$a_01_4 = {53 65 74 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 } //00 00  SetUnhandledExceptionFilter
	condition:
		any of ($a_*)
 
}