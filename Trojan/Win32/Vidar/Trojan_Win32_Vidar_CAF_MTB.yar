
rule Trojan_Win32_Vidar_CAF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 50 48 50 51 47 34 31 4e 42 31 55 46 33 55 } //1 IPHPQG41NB1UF3U
		$a_01_1 = {57 44 4b 46 4f 42 55 39 47 36 32 59 44 4d 43 32 55 39 4c 55 44 5a 4e 50 35 } //1 WDKFOBU9G62YDMC2U9LUDZNP5
		$a_01_2 = {4e 4b 4f 57 53 42 54 4b 49 35 4a 4e 4a 43 49 4e 51 41 36 49 56 } //1 NKOWSBTKI5JNJCINQA6IV
		$a_01_3 = {56 36 35 30 58 38 41 5a 4a 49 33 4b } //1 V650X8AZJI3K
		$a_01_4 = {45 57 34 54 5a 4a 4b 4e 39 36 45 55 30 4d } //1 EW4TZJKN96EU0M
		$a_01_5 = {63 68 65 63 6b 70 6f 69 6e 74 65 64 } //1 checkpointed
		$a_01_6 = {77 61 6c 5f 61 75 74 6f 63 68 65 63 6b 70 6f 69 6e 74 } //1 wal_autocheckpoint
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}