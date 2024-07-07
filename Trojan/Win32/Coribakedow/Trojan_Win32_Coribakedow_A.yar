
rule Trojan_Win32_Coribakedow_A{
	meta:
		description = "Trojan:Win32/Coribakedow.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_80_0 = {5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 72 65 73 65 72 76 65 2e 65 78 65 } //\Users\Public\reserve.exe  10
		$a_80_1 = {52 45 47 20 41 44 44 20 22 48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2f 56 20 22 6d 69 63 72 6f 73 6f 66 74 20 75 70 64 61 74 65 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 46 20 2f 44 20 22 53 43 48 54 41 53 4b 53 20 2f 72 75 6e 20 2f 74 6e } //REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "microsoft update" /t REG_SZ /F /D "SCHTASKS /run /tn  10
		$a_80_2 = {6d 69 63 72 6f 73 6f 66 74 65 73 74 6f 72 65 2e 74 6f 70 } //microsoftestore.top  1
		$a_80_3 = {6d 69 63 72 6f 73 6f 66 74 73 79 73 74 65 6d 63 6c 6f 75 64 2e 63 6f 6d } //microsoftsystemcloud.com  1
		$a_80_4 = {63 68 61 73 65 6c 74 64 2e 74 6f 70 } //chaseltd.top  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=21
 
}