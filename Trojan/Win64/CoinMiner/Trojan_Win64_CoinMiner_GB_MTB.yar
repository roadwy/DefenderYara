
rule Trojan_Win64_CoinMiner_GB_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 0a 00 "
		
	strings :
		$a_80_0 = {2d 2d 64 6f 6e 61 74 65 2d 6c } //--donate-l  0a 00 
		$a_80_1 = {53 65 6c 65 63 74 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 77 68 65 72 65 20 4e 61 6d 65 3d 27 7b 30 7d 27 } //Select CommandLine from Win32_Process where Name='{0}'  01 00 
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  01 00 
		$a_80_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //CreateEncryptor  01 00 
		$a_80_4 = {57 61 74 63 68 64 6f 67 } //Watchdog  01 00 
		$a_80_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  01 00 
		$a_80_6 = {5c 72 6f 6f 74 5c 63 69 6d 76 32 } //\root\cimv2  00 00 
	condition:
		any of ($a_*)
 
}