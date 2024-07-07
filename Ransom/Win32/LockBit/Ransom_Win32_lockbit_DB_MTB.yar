
rule Ransom_Win32_lockbit_DB_MTB{
	meta:
		description = "Ransom:Win32/lockbit.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 6f 72 20 42 72 6f 77 73 65 72 20 6d 61 79 20 62 65 20 62 6c 6f 63 6b 65 64 20 69 6e 20 79 6f 75 72 20 63 6f 75 6e 74 72 79 20 6f 72 20 63 6f 72 70 6f 72 61 74 65 20 6e 65 74 77 6f 72 6b } //1 Tor Browser may be blocked in your country or corporate network
		$a_81_1 = {52 65 73 74 6f 72 65 2d 4d 79 2d 46 69 6c 65 73 2e 74 78 74 } //1 Restore-My-Files.txt
		$a_81_2 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_81_3 = {67 65 74 68 6f 73 74 62 79 61 64 64 72 } //1 gethostbyaddr
		$a_81_4 = {42 43 72 79 70 74 47 65 6e 52 61 6e 64 6f 6d } //1 BCryptGenRandom
		$a_81_5 = {63 72 65 61 73 65 64 20 70 72 69 63 65 } //1 creased price
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}