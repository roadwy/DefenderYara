
rule Ransom_Win64_BQTLock_PA_MTB{
	meta:
		description = "Ransom:Win64/BQTLock.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 6d 70 5c 62 71 74 5f 70 61 79 6c 6f 61 64 2e 65 78 65 } //5 Temp\bqt_payload.exe
		$a_01_1 = {54 65 6d 70 5c 62 71 74 5f 77 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //1 Temp\bqt_wallpaper.bmp
		$a_01_2 = {54 65 6d 70 5c 62 71 74 5f 73 63 72 65 65 6e 73 68 6f 74 } //1 Temp\bqt_screenshot
		$a_01_3 = {42 51 54 4c 6f 63 6b 20 50 61 79 6c 6f 61 64 20 73 74 61 72 74 65 64 } //1 BQTLock Payload started
		$a_01_4 = {41 20 6e 65 77 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 21 } //1 A new system has been infected!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}
rule Ransom_Win64_BQTLock_PA_MTB_2{
	meta:
		description = "Ransom:Win64/BQTLock.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 62 71 74 5f 6c 6f 67 2e 74 78 74 } //6 C:\Windows\Temp\bqt_log.txt
		$a_01_1 = {42 51 54 4c 6f 63 6b 20 52 65 70 6f 72 74 } //1 BQTLock Report
		$a_01_2 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 files have been encrypted
		$a_01_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin.exe delete shadows /all /quiet
		$a_01_4 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //1 bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
		$a_01_5 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 64 65 73 74 72 6f 79 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 61 6e 64 20 72 65 63 6f 76 65 72 79 20 6f 70 74 69 6f 6e 73 2e } //1 Attempting to destroy shadow copies and recovery options.
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}