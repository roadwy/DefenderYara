
rule Trojan_Win32_CryptInject_AG_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 49 00 6e 00 74 00 65 00 6c 00 5c 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 42 00 72 00 6f 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  %s\Intel\RuntimeBroker.exe
		$a_01_1 = {5c 00 5c 00 2e 00 5c 00 50 00 69 00 70 00 65 00 5c 00 43 00 68 00 65 00 63 00 6b 00 4f 00 6e 00 65 00 } //01 00  \\.\Pipe\CheckOne
		$a_01_2 = {46 75 63 6b 69 6e 67 53 68 69 74 6f 6e 41 6c 6c 45 61 72 74 68 23 36 36 36 } //01 00  FuckingShitonAllEarth#666
		$a_01_3 = {79 73 68 33 6b 73 6b 64 66 68 32 4a 4b 4a 46 64 73 6b 66 68 41 44 36 36 36 } //00 00  ysh3kskdfh2JKJFdskfhAD666
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_CryptInject_AG_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.AG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 69 73 65 5c 57 69 6e 64 6f 77 5c 70 6f 73 69 74 69 6f 6e 5c 43 68 61 72 61 63 74 65 72 5c 6f 70 70 6f 73 69 74 65 5c 4d 69 73 73 5c 6c 61 77 43 6f 6d 65 2e 70 64 62 } //00 00  rise\Window\position\Character\opposite\Miss\lawCome.pdb
	condition:
		any of ($a_*)
 
}