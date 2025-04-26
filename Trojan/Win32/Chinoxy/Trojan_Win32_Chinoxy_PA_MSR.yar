
rule Trojan_Win32_Chinoxy_PA_MSR{
	meta:
		description = "Trojan:Win32/Chinoxy.PA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 72 65 67 20 44 45 4c 45 54 45 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 48 75 78 39 31 20 2f 66 } //1 @reg DELETE HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v Hux91 /f
		$a_01_1 = {72 65 67 2e 65 78 65 20 61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 20 2f 76 20 48 75 78 39 31 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 73 20 2f 66 } //1 reg.exe add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v Hux91 /t REG_SZ /d %s /f
		$a_00_2 = {5c 00 74 00 61 00 73 00 6b 00 73 00 5c 00 69 00 6e 00 66 00 6f 00 6b 00 65 00 79 00 2e 00 64 00 61 00 74 00 } //1 \tasks\infokey.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}