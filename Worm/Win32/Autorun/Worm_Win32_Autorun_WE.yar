
rule Worm_Win32_Autorun_WE{
	meta:
		description = "Worm:Win32/Autorun.WE,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 20 50 6f 72 20 65 6a 65 6d 70 6c 6f 3a } //1 # Por ejemplo:
		$a_01_1 = {31 32 37 2e 30 2e 30 2e 31 20 6b 61 73 70 65 72 73 6b 79 2d 6c 61 62 73 2e 63 6f 6d 20 } //1 127.0.0.1 kaspersky-labs.com 
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 3d 4f 70 65 6e } //1 shell\open=Open
		$a_01_3 = {6b 69 6c 6c 65 72 6d 73 63 6f 6e 66 69 67 } //1 killermsconfig
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 C:\WINDOWS\SYSTEM32\MSVBVM60.DLL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}