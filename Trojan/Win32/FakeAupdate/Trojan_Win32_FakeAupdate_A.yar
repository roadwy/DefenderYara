
rule Trojan_Win32_FakeAupdate_A{
	meta:
		description = "Trojan:Win32/FakeAupdate.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 65 72 20 6c 75 6d 69 20 31 2e 31 5c 66 69 6e 61 6c 32 20 2d 20 43 6f 70 69 65 } //1 crypter lumi 1.1\final2 - Copie
		$a_01_1 = {44 76 56 41 2f 73 6b 32 35 4e 50 45 70 64 6d 70 47 74 57 42 } //1 DvVA/sk25NPEpdmpGtWB
		$a_01_2 = {61 64 6f 62 65 55 70 64 61 74 65 72 2e 65 78 65 } //1 adobeUpdater.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}