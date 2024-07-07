
rule Trojan_Win32_Killav_FA{
	meta:
		description = "Trojan:Win32/Killav.FA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_01_1 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 33 36 30 } //1 system32\drivers\360
		$a_01_2 = {5c 5c 2e 5c 4b 69 6c 6c 50 72 6f 63 65 73 73 } //1 \\.\KillProcess
		$a_01_3 = {75 09 66 81 7c 30 fe c7 05 74 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}