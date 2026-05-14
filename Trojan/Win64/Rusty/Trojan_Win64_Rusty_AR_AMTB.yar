
rule Trojan_Win64_Rusty_AR_AMTB{
	meta:
		description = "Trojan:Win64/Rusty.AR!AMTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {31 39 33 2e 31 36 31 2e 31 39 33 2e 39 39 } //5 193.161.193.99
		$a_01_1 = {63 6c 65 61 6e 75 70 2e 62 61 74 } //5 cleanup.bat
		$a_01_2 = {75 6e 69 6e 73 74 61 6c 6c 6b 69 6c 6c 63 64 20 63 6d 64 2f 43 45 72 72 3a } //1 uninstallkillcd cmd/CErr:
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 22 22 20 3e 6e 75 6c 20 32 3e 26 31 } //1 taskkill /F /IM "" >nul 2>&1
		$a_01_4 = {74 69 6d 65 6f 75 74 20 2f 74 20 31 20 2f 6e 6f 62 72 65 61 6b 20 3e 6e 75 6c } //1 timeout /t 1 /nobreak >nul
		$a_01_5 = {48 65 61 6c 74 68 4d 6f 6e 2e 65 78 65 63 6d 64 61 74 74 72 69 62 20 2b 68 } //1 HealthMon.execmdattrib +h
		$a_01_6 = {61 20 73 70 61 77 6e 65 64 20 74 61 73 6b 20 70 61 6e 69 63 6b 65 64 20 61 6e 64 20 74 68 65 20 72 75 6e 74 69 6d 65 20 69 73 20 63 6f 6e 66 69 67 75 72 65 64 20 74 6f 20 73 68 75 74 20 64 6f 77 6e 20 6f 6e 20 75 6e 68 61 6e 64 6c 65 64 20 70 61 6e 69 63 } //1 a spawned task panicked and the runtime is configured to shut down on unhandled panic
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}