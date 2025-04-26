
rule Trojan_Win32_CrthRazy_A{
	meta:
		description = "Trojan:Win32/CrthRazy.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 53 61 66 65 20 42 72 6f 77 73 69 6e 67 20 45 78 74 65 6e 73 69 6f 6e 20 42 6c 61 63 6b 6c 69 73 74 } //1 \Safe Browsing Extension Blacklist
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 59 61 6e 64 65 78 42 72 6f 77 73 65 72 } //1 Software\Policies\YandexBrowser
		$a_01_2 = {2f 4d 6f 64 75 6c 61 72 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 /ModularInstaller.exe
		$a_01_3 = {2f 53 20 2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 } //1 /S /C choice /C Y /N /D Y /T 3
		$a_01_4 = {7b 46 41 31 42 37 32 37 44 2d 33 39 37 30 2d 34 35 36 } //1 {FA1B727D-3970-456
		$a_01_5 = {31 2d 38 41 43 36 2d 41 43 38 41 41 37 44 42 41 36 33 39 7d } //1 1-8AC6-AC8AA7DBA639}
		$a_01_6 = {48 41 52 44 57 41 52 45 5c 44 45 53 43 52 49 50 54 49 4f 4e 5c 53 79 73 74 65 6d 5c 42 69 6f 73 } //1 HARDWARE\DESCRIPTION\System\Bios
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}