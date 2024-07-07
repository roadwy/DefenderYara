
rule Backdoor_Win32_Usinec_D{
	meta:
		description = "Backdoor:Win32/Usinec.D,SIGNATURE_TYPE_PEHSTR,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 } //1 Windows NT\CurrentVersion\Winlogon\Notify
		$a_01_1 = {53 75 70 70 6f 72 74 20 55 53 42 33 20 53 65 72 76 69 63 65 } //1 Support USB3 Service
		$a_01_2 = {4e 45 55 53 42 77 33 32 2e 64 6c 6c } //1 NEUSBw32.dll
		$a_01_3 = {55 53 42 33 53 77 33 32 2e 64 6c 6c } //1 USB3Sw32.dll
		$a_01_4 = {75 73 62 6e 61 77 33 32 2e 64 6c 6c } //1 usbnaw32.dll
		$a_01_5 = {75 73 62 6e 69 77 33 32 2e 64 6c 6c } //1 usbniw32.dll
		$a_01_6 = {7b 73 79 73 7d 5c 69 74 6c 73 76 63 2e 64 61 74 } //1 {sys}\itlsvc.dat
		$a_01_7 = {68 74 74 70 3a 2f 2f 68 61 6e 64 6a 6f 62 68 65 61 74 73 2e 63 6f 6d 2f 78 67 69 2d 62 69 6e 2f 71 2e 70 68 70 } //1 http://handjobheats.com/xgi-bin/q.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}