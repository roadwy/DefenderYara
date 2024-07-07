
rule Trojan_Win32_Lockscreen_AMMD_MTB{
	meta:
		description = "Trojan:Win32/Lockscreen.AMMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 49 4e 4c 4f 43 4b 42 59 41 4d 50 42 59 41 4d 50 42 59 41 4d 50 66 73 64 6a 66 } //WINLOCKBYAMPBYAMPBYAMPfsdjf  2
		$a_80_1 = {43 3a 5c 4d 42 52 2e 62 69 6e } //C:\MBR.bin  2
		$a_80_2 = {44 69 73 61 62 6c 65 43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 } //DisableChangePassword  2
		$a_80_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6d 6f 6e 6b 65 69 69 69 2e 64 6c 6c } //C:\Users\Public\monkeiii.dll  2
		$a_80_4 = {2f 63 20 54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 46 49 20 22 49 6d 61 67 65 6e 61 6d 65 20 6e 65 } ///c TASKKILL /F /FI "Imagename ne  2
		$a_80_5 = {41 6e 74 69 57 69 6e 4c 6f 63 6b 65 72 54 72 61 79 2e 65 78 65 } //AntiWinLockerTray.exe  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=12
 
}