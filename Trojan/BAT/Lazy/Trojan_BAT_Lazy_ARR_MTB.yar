
rule Trojan_BAT_Lazy_ARR_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 07 2d 04 16 0a 2b 6e 07 02 7b } //9
		$a_01_1 = {2d 04 16 0a 2b 47 02 07 02 7b } //11 Эਖ䜫܂笂
	condition:
		((#a_01_0  & 1)*9+(#a_01_1  & 1)*11) >=20
 
}
rule Trojan_BAT_Lazy_ARR_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_03_0 = {70 00 61 00 73 00 74 00 65 00 66 00 79 00 2e 00 61 00 70 00 70 00 2f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 00 72 00 61 00 77 00 20 00 2d 00 55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //15
		$a_03_1 = {70 61 73 74 65 66 79 2e 61 70 70 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2f 72 61 77 20 2d 55 73 65 42 61 73 69 63 50 61 72 73 69 6e 67 } //15
		$a_03_2 = {64 00 61 00 79 00 64 00 65 00 6f 00 6e 00 63 00 68 00 61 00 75 00 6f 00 69 00 5f 00 [0-02] 2e 00 65 00 78 00 65 00 } //5
		$a_03_3 = {64 61 79 64 65 6f 6e 63 68 61 75 6f 69 5f [0-02] 2e 65 78 65 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*15+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=20
 
}
rule Trojan_BAT_Lazy_ARR_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_81_0 = {2a 48 75 62 4c 61 75 6e 63 68 65 72 2e 4d 61 69 6e 57 69 6e 64 6f 77 2b 3c 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 3e 64 5f 5f 36 34 } //10 *HubLauncher.MainWindow+<DownloadFile>d__64
		$a_81_1 = {4e 49 47 45 52 2e } //9 NIGER.
		$a_81_2 = {31 3d 31 44 31 4b 31 52 31 58 31 5e 31 63 31 6a 31 71 31 77 31 7c 31 } //5 1=1D1K1R1X1^1c1j1q1w1|1
		$a_81_3 = {42 34 36 39 76 79 66 6e 65 5a 6c 61 31 51 78 4c 77 6f 64 42 39 4d 46 78 4b 65 51 65 71 4d 6c 34 63 57 67 36 67 55 33 49 4f 55 45 30 74 4c 33 75 61 38 56 6a 75 6d 58 66 64 55 2f 2b 73 6d 47 50 39 58 77 34 31 54 2b 66 39 67 74 6f 63 53 44 } //2 B469vyfneZla1QxLwodB9MFxKeQeqMl4cWg6gU3IOUE0tL3ua8VjumXfdU/+smGP9Xw41T+f9gtocSD
		$a_81_4 = {54 6b 6c 48 52 56 49 75 35 72 57 70 36 5a 69 7a 35 72 4b 49 36 62 4b 42 35 5a 4b 4d 35 62 4b 62 35 6f 69 51 35 72 75 6f 36 59 4f 39 35 71 32 6d } //1 TklHRVIu5rWp6Ziz5rKI6bKB5ZKM5bKb5oiQ5ruo6YO95q2m
		$a_81_5 = {53 61 76 65 43 72 65 64 65 6e 74 69 61 6c 73 } //3 SaveCredentials
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*9+(#a_81_2  & 1)*5+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*3) >=30
 
}