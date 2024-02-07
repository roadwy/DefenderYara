
rule Trojan_BAT_Kryptik_FI_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {11 04 13 05 11 05 1f 41 32 06 11 05 1f 4d } //0a 00  Бԓԑ䄟زԑ䴟
		$a_00_1 = {11 05 1f 4e 32 06 11 05 1f 5a 31 14 11 05 1f } //02 00 
		$a_80_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  02 00 
		$a_80_3 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Kryptik_FI_MTB_2{
	meta:
		description = "Trojan:BAT/Kryptik.FI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {7e 82 d2 52 26 06 47 06 62 00 e7 05 53 00 c1 79 46 06 56 00 26 06 4a 00 43 06 47 06 2d 06 } //01 00 
		$a_80_1 = {49 6e 24 4a 24 63 74 30 72 } //In$J$ct0r  01 00 
		$a_00_2 = {57 00 7e 82 7e 82 86 06 27 06 58 00 4f 00 6c 9a 4e 30 4c 00 4d 00 d6 05 d4 05 51 00 51 00 } //01 00 
		$a_80_3 = {6b 57 4a 47 67 78 57 6d 38 4c 45 55 51 35 38 45 48 31 45 42 65 48 79 70 75 53 } //kWJGgxWm8LEUQ58EH1EBeHypuS  01 00 
		$a_80_4 = {41 70 24 70 24 65 78 } //Ap$p$ex  00 00 
	condition:
		any of ($a_*)
 
}