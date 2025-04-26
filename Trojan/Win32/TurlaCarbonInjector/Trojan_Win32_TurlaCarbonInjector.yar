
rule Trojan_Win32_TurlaCarbonInjector{
	meta:
		description = "Trojan:Win32/TurlaCarbonInjector,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 52 65 73 53 76 63 } //1 WinResSvc
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 4d 53 53 56 43 43 46 47 2e 64 6c 6c } //1 C:\Program Files\Windows NT\MSSVCCFG.dll
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 73 65 74 20 75 70 20 73 65 72 76 69 63 65 2e 20 45 72 72 6f 72 20 63 6f 64 65 3a 20 25 64 } //1 Failed to set up service. Error code: %d
		$a_01_3 = {56 69 72 74 75 61 6c 51 75 65 72 79 20 66 61 69 6c 65 64 20 66 6f 72 20 25 64 20 62 79 74 65 73 20 61 74 20 61 64 64 72 65 73 73 20 25 70 } //1 VirtualQuery failed for %d bytes at address %p
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 20 66 61 69 6c 65 64 20 77 69 74 68 20 63 6f 64 65 20 30 78 25 78 } //1 VirtualProtect failed with code 0x%x
		$a_01_5 = {25 70 20 6e 6f 74 20 66 6f 75 6e 64 3f 21 3f 21 } //1 %p not found?!?!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}