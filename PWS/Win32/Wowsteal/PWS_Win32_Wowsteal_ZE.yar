
rule PWS_Win32_Wowsteal_ZE{
	meta:
		description = "PWS:Win32/Wowsteal.ZE,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //10 VirtualAllocEx
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {54 68 69 73 20 70 72 6f 6b 6b 6b 69 20 6d 75 73 74 20 62 65 20 72 75 6e 20 75 6e 64 65 72 20 57 69 6e 33 32 } //10 This prokkki must be run under Win32
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}