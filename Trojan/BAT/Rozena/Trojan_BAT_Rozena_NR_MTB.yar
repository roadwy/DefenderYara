
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
		description = "Trojan:BAT/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 27 00 00 0a 1f 28 58 13 0b 11 0a 11 0b 28 ?? ?? ?? 0a 6e 11 09 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 13 0c 20 ?? ?? ?? 00 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a } //5
		$a_01_1 = {68 00 61 00 73 00 6e 00 61 00 69 00 6e 00 77 00 69 00 6e 00 73 00 } //1 hasnainwins
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}