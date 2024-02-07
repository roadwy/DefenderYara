
rule Trojan_Win32_Winnti_F_dha{
	meta:
		description = "Trojan:Win32/Winnti.F!dha,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 7c 24 29 5a 75 0d } //01 00 
		$a_01_1 = {5c 3f 3f 5c 25 73 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //01 00  \??\%s\drivers\%s.sys
		$a_01_2 = {47 6c 6f 62 61 6c 5c 25 73 } //01 00  Global\%s
		$a_01_3 = {63 6d 64 3d 30 78 25 58 } //01 00  cmd=0x%X
		$a_01_4 = {4c 73 63 73 76 63 2e 64 6c 6c } //01 00  Lscsvc.dll
		$a_01_5 = {75 73 62 6d 73 67 } //01 00  usbmsg
		$a_01_6 = {43 4f 4e 4e 45 43 54 20 25 73 3a 25 64 20 48 54 54 50 2f 31 2e 31 } //00 00  CONNECT %s:%d HTTP/1.1
	condition:
		any of ($a_*)
 
}