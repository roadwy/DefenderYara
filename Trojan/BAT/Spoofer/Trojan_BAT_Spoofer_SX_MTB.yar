
rule Trojan_BAT_Spoofer_SX_MTB{
	meta:
		description = "Trojan:BAT/Spoofer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 6f 6f 66 65 72 2e 65 78 65 } //20 spoofer.exe
		$a_80_1 = {64 65 6c 20 2f 79 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 63 6f 6f 6b 69 65 73 } //del /y c:\windows\cookies  15
		$a_80_2 = {5b 34 5d 20 55 6e 6c 69 6e 6b 20 44 69 73 63 6f 72 64 } //[4] Unlink Discord  10
		$a_80_3 = {52 45 47 20 44 45 4c 45 54 45 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 4c 69 63 65 6e 73 69 6e 67 5c 48 61 72 64 77 61 72 65 49 44 20 2f 66 } //REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSLicensing\HardwareID /f  10
		$a_80_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 53 74 65 61 6d 2e 65 78 65 20 2f 74 } //taskkill /f /im Steam.exe /t  5
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*15+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*5) >=60
 
}