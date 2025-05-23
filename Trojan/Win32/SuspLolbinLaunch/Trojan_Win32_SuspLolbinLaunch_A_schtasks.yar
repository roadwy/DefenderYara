
rule Trojan_Win32_SuspLolbinLaunch_A_schtasks{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.A!schtasks,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 } //1 schtasks.exe
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 /create
		$a_00_2 = {2f 00 72 00 75 00 6e 00 } //-10 /run
		$a_00_3 = {44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 69 00 73 00 5c 00 5a 00 75 00 75 00 6d 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //-10 Diagnosis\ZuumMonitoring
		$a_00_4 = {41 00 6c 00 65 00 72 00 74 00 75 00 73 00 53 00 65 00 63 00 75 00 72 00 65 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 } //-10 AlertusSecureDesktopLauncher
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-10+(#a_00_3  & 1)*-10+(#a_00_4  & 1)*-10) >=2
 
}
rule Trojan_Win32_SuspLolbinLaunch_A_schtasks_2{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.A!schtasks,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_00_0 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //10
		$a_00_1 = {20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 } //1  /Create 
		$a_00_2 = {20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 53 00 54 00 41 00 52 00 54 00 20 00 } //1  /SC ONSTART 
		$a_02_3 = {20 00 2f 00 52 00 55 00 20 00 [0-04] 4e 00 54 00 20 00 41 00 55 00 54 00 48 00 4f 00 52 00 49 00 54 00 59 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 } //1
		$a_02_4 = {20 00 2f 00 54 00 4e 00 20 00 90 29 20 00 20 00 } //1
		$a_02_5 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-08] 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //1
		$a_02_6 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-08] 5c 00 5c 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1) >=15
 
}