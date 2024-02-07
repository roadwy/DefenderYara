
rule Trojan_Win32_Floyadi_A_bit{
	meta:
		description = "Trojan:Win32/Floyadi.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 4b 58 4f 53 55 4b } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run\KXOSUK
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 63 74 2e 65 78 65 } //01 00  C:\WINDOWS\system32\svchoct.exe
		$a_01_2 = {5c 52 75 69 6b 6f 70 2e 65 78 65 } //00 00  \Ruikop.exe
		$a_00_3 = {5d 04 00 } //00 e3 
	condition:
		any of ($a_*)
 
}