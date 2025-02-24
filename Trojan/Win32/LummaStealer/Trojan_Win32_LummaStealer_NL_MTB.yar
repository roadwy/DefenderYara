
rule Trojan_Win32_LummaStealer_NL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 02 8b e9 33 c0 33 ff 3b eb 74 2e } //3
		$a_03_1 = {e8 36 fa ff ff 83 c4 ?? 80 7e 48 00 75 10 85 c0 78 0c 8b 4c 24 14 88 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win32_LummaStealer_NL_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {7c 16 43 33 f6 8b 47 ?? 8b d6 e8 e3 08 fc ff e8 26 fd fa ff 46 4b 75 ed } //5
		$a_01_1 = {44 69 65 64 48 69 73 74 6f 72 69 63 } //1 DiedHistoric
		$a_01_2 = {41 6e 64 72 65 77 73 20 53 69 67 6e 65 64 20 53 79 6d 70 6f 73 69 75 6d 20 43 61 72 74 20 4e 61 74 69 6f 6e 20 45 75 72 6f 73 } //1 Andrews Signed Symposium Cart Nation Euros
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_Win32_LummaStealer_NL_MTB_3{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 ?? 8a 4c 24 ?? 84 88 e1 8d ce 00 75 1e 83 7c 24 ?? 00 e9 fa 18 00 00 7f 72 00 0f b7 04 41 23 44 24 ?? eb 02 33 c0 85 c0 75 01 } //2
		$a_03_1 = {8b 0e 89 48 0c 8b 4d ?? 89 48 04 8b 4d ?? 89 48 08 8b 0d 50 dc c4 00 47 89 58 18 89 48 1c 3b 7d ?? a3 50 dc c4 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_Win32_LummaStealer_NL_MTB_4{
	meta:
		description = "Trojan:Win32/LummaStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 13 8d 05 a0 3a 14 03 89 10 89 42 18 e8 55 14 00 00 fc e8 6f b9 fd ff 8b 44 24 78 89 04 24 8b 44 24 7c 89 44 24 04 } //3
		$a_01_1 = {8b 7c 24 04 8b 15 b4 3a 18 03 64 8b 12 8b 02 8b 1c 24 89 58 20 8d 5c 24 } //2
		$a_01_2 = {70 61 79 6c 6f 61 64 54 79 70 65 } //1 payloadType
		$a_01_3 = {4c 41 55 4e 43 48 5f 53 54 41 47 45 5f 55 4e 53 50 45 43 49 46 49 45 44 } //1 LAUNCH_STAGE_UNSPECIFIED
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}