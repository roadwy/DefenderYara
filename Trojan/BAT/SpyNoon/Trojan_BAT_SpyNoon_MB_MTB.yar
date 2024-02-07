
rule Trojan_BAT_SpyNoon_MB_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 00 65 00 72 00 67 00 65 00 65 00 67 00 64 00 32 00 65 00 } //01 00  Eergeegd2e
		$a_01_1 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_01_2 = {59 00 65 00 65 00 6f 00 53 00 68 00 67 00 64 00 58 00 6a 00 6d 00 39 00 48 00 4d 00 59 00 4d 00 58 00 6f 00 59 00 } //01 00  YeeoShgdXjm9HMYMXoY
		$a_01_3 = {43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 5f 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e } //01 00  CurrentDomain_UnhandledException
		$a_01_4 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}