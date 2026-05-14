
rule Trojan_Win32_BurrowShell_AMTB{
	meta:
		description = "Trojan:Win32/BurrowShell!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 55 73 65 72 73 5c 70 61 6b 69 73 5c 2e 63 61 72 67 6f 5c 72 65 67 69 73 74 72 79 5c 73 72 63 5c 69 6e 64 65 78 2e 63 72 61 74 65 73 2e 69 6f 2d 31 39 34 39 63 66 38 63 36 62 35 62 35 35 37 66 5c } //C:\Users\pakis\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\  5
		$a_80_1 = {73 74 61 72 74 20 6b 65 79 6c 6f 67 73 74 6f 70 20 6b 65 79 6c 6f 67 73 63 72 65 65 6e 73 68 6f 74 64 6f 77 6e 6c 6f 61 64 20 45 72 72 6f 72 20 75 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 3a } //start keylogstop keylogscreenshotdownload Error uploading file:  2
		$a_80_2 = {53 6c 65 65 70 20 69 72 72 65 67 75 6c 61 72 69 74 79 3a 20 73 6c 65 70 74 20 66 6f 72 20 73 20 69 6e 73 74 65 61 64 20 6f 66 20 63 61 6c 63 75 6c 61 74 65 64 20 73 20 28 62 61 73 65 3a 20 73 2c 20 6a 69 74 74 65 72 3a 20 25 29 } //Sleep irregularity: slept for s instead of calculated s (base: s, jitter: %)  2
		$a_80_3 = {43 4f 4d 50 55 54 45 52 4e 41 4d 45 55 53 45 52 4e 41 4d 45 68 6f 73 74 6e 61 6d 65 77 68 6f 61 6d 69 52 65 67 69 73 74 72 61 74 69 6f 6e 20 66 61 69 6c 65 64 20 61 66 74 65 72 20 20 61 74 74 65 6d 70 74 73 3a } //COMPUTERNAMEUSERNAMEhostnamewhoamiRegistration failed after  attempts:  2
		$a_80_4 = {4b 65 79 6c 6f 67 67 65 72 20 73 74 61 72 74 65 64 4b 65 79 6c 6f 67 67 65 72 20 69 73 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 69 6f 6e 20 74 6f 6f 6b 20 } //Keylogger startedKeylogger is already runningCommand execution took   2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=13
 
}