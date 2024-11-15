
rule Trojan_BAT_Rozena_NR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 01 00 00 06 0b 16 07 06 28 ?? 00 00 0a 7e ?? 00 00 0a 16 07 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15 } //5
		$a_01_1 = {4f 66 66 65 6e 73 69 76 65 53 68 61 72 70 } //1 OffensiveSharp
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Rozena_NR_MTB_2{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 28 28 2a 00 00 0a 6e 06 1f 2c 28 ?? ?? ?? 0a 6e 0c 28 ?? ?? ?? 06 6e 08 28 ?? ?? ?? 06 6e 0c 20 ?? ?? ?? 00 6a 5a 08 20 ?? ?? ?? 00 6a 5a } //5
		$a_01_1 = {43 53 68 61 72 70 4c 6f 61 64 65 72 41 45 53 6b 65 79 } //1 CSharpLoaderAESkey
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Rozena_NR_MTB_3{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 72 70 07 00 70 6f 14 00 00 0a 0b 28 ?? 00 00 0a 72 b2 07 00 70 6f 14 00 00 0a 0c 28 ?? 00 00 0a 07 08 28 ?? 00 00 06 0d 09 8e 69 13 04 } //3
		$a_01_1 = {45 76 61 73 69 6f 6e 53 75 69 74 65 2e 70 64 62 } //1 EvasionSuite.pdb
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Rozena_NR_MTB_4{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 27 00 00 0a 1f 28 58 13 0b 11 0a 11 0b 28 ?? ?? ?? 0a 6e 11 09 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 13 0c 20 ?? ?? ?? 00 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a } //5
		$a_01_1 = {68 00 61 00 73 00 6e 00 61 00 69 00 6e 00 77 00 69 00 6e 00 73 00 } //1 hasnainwins
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Rozena_NR_MTB_5{
	meta:
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 04 8e 69 13 05 7e ?? 00 00 0a 20 00 10 00 00 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 06 11 04 16 11 06 11 05 } //3
		$a_03_1 = {7e 13 00 00 0a 16 11 06 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 13 07 11 07 15 28 ?? 00 00 06 26 } //3
		$a_01_2 = {73 68 61 6e 65 6b 68 61 6e 74 61 75 6e 39 } //1 shanekhantaun9
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}