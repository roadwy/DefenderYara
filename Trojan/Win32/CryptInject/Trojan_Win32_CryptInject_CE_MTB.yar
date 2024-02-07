
rule Trojan_Win32_CryptInject_CE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 42 49 4d 41 47 45 2e 44 4c 4c } //01 00  FBIMAGE.DLL
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 } //01 00  c:\windows\temp
		$a_81_2 = {63 68 69 6e 67 73 40 31 36 33 2e 6e 65 74 } //01 00  chings@163.net
		$a_81_3 = {46 69 72 65 62 69 72 64 20 57 6f 72 6b 72 6f 6f 6d } //01 00  Firebird Workroom
		$a_01_4 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //01 00  UnhookWindowsHookEx
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00  VirtualAlloc
	condition:
		any of ($a_*)
 
}