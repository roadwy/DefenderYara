
rule Trojan_Win64_CobaltStrike_MB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 33 c0 41 b9 9e 03 00 00 49 8b c0 49 ff c0 83 e0 0f 8a 04 10 30 01 48 ff c1 49 83 e9 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c1 89 87 90 01 04 8b 0d 90 01 04 8b 05 90 01 04 ff c0 0f af c8 89 0d 90 01 04 49 81 f8 90 00 } //01 00 
		$a_03_1 = {88 14 01 ff 05 90 01 04 48 8b 15 90 01 04 8b 82 90 01 04 8b 8a 90 01 04 33 c8 81 e9 90 01 04 0f af c8 89 8a 90 01 04 48 8b 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MB_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 54 84 18 89 d5 c1 c5 90 02 01 89 d3 c1 c3 90 02 01 c1 ea 90 02 01 31 da 31 ea 8b 6c 84 90 02 01 8b 5c 84 90 02 01 89 df c1 c7 90 02 01 89 de c1 c6 90 02 01 c1 eb 90 02 01 31 f3 31 fb 03 6c 84 90 02 01 01 d5 01 dd 89 6c 84 90 02 01 48 83 c0 90 02 01 48 83 f8 90 02 01 75 90 00 } //01 00 
		$a_01_1 = {62 72 6f 6b 65 6e 20 70 69 70 65 } //01 00  broken pipe
		$a_01_2 = {63 6f 6e 6e 65 63 74 69 6f 6e 20 61 62 6f 72 74 65 64 } //01 00  connection aborted
		$a_01_3 = {6f 77 6e 65 72 20 64 65 61 64 } //00 00  owner dead
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MB_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 41 78 67 44 4d 78 75 4b 7a 4c 55 } //02 00  AAxgDMxuKzLU
		$a_01_1 = {41 4f 4f 75 43 68 72 54 49 54 4e 79 50 67 64 6b 4a 6a 46 50 54 6e 42 } //02 00  AOOuChrTITNyPgdkJjFPTnB
		$a_01_2 = {41 58 4d 71 6e 78 6c 4a 7a 44 58 4b 4b 4e 46 67 77 4d 43 72 4a 55 6b } //02 00  AXMqnxlJzDXKKNFgwMCrJUk
		$a_01_3 = {42 59 7a 7a 42 7a 57 56 62 4e 6a 4b 64 58 70 4f 50 68 41 6d } //02 00  BYzzBzWVbNjKdXpOPhAm
		$a_01_4 = {43 43 68 51 52 79 55 56 69 6b 4d 61 42 47 44 45 47 75 6c 72 } //02 00  CChQRyUVikMaBGDEGulr
		$a_01_5 = {43 57 45 4d 52 76 77 74 4a 4e 6f 76 72 72 57 73 49 77 45 52 6a 53 6a 44 } //02 00  CWEMRvwtJNovrrWsIwERjSjD
		$a_01_6 = {43 6a 6a 42 74 5a 4c 5a 6b 4b 64 6b 4d 66 52 70 6c 41 57 } //02 00  CjjBtZLZkKdkMfRplAW
		$a_01_7 = {44 43 51 74 78 6c 4a 69 74 4d 72 71 4c 57 7a 79 } //02 00  DCQtxlJitMrqLWzy
		$a_01_8 = {44 54 5a 4e 51 78 59 4f 58 49 6f 74 75 72 7a 48 72 45 7a 52 70 78 75 } //00 00  DTZNQxYOXIoturzHrEzRpxu
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_MB_MTB_5{
	meta:
		description = "Trojan:Win64/CobaltStrike.MB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 83 80 00 00 00 48 8b 8b e0 00 00 00 42 31 04 01 49 83 c0 04 8b 83 e8 00 00 00 01 83 80 00 00 00 8b 43 24 ff c8 01 83 d0 00 00 00 8b 83 94 00 00 00 8b 93 a8 00 00 00 81 c2 37 9f fd ff 03 53 74 0f af c2 89 83 94 00 00 00 b8 6f 15 f8 ff } //00 00 
	condition:
		any of ($a_*)
 
}