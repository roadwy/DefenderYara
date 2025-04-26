
rule Backdoor_Win32_DarkGate_FF_dha{
	meta:
		description = "Backdoor:Win32/DarkGate.FF!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 6d 70 70 5c 61 75 74 6f 69 74 33 2e 65 78 65 20 63 3a 5c 74 6d 70 70 5c 74 65 73 74 2e 61 75 33 } //1 c:\tmpp\autoit3.exe c:\tmpp\test.au3
		$a_01_1 = {44 65 62 75 67 43 6f 6e 6e 65 63 74 57 69 64 65 } //1 DebugConnectWide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}