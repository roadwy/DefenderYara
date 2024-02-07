
rule Trojan_Win32_Emulga_A{
	meta:
		description = "Trojan:Win32/Emulga.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 20 45 78 70 6c 6f 72 65 72 20 63 64 72 6f 6d 20 6f 70 74 69 6d 69 7a 65 72 } //01 00  Windows Explorer cdrom optimizer
		$a_01_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  DllCanUnloadNow
		$a_01_2 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //01 00  DllGetClassObject
		$a_01_3 = {47 65 74 44 6f 6d 65 6e } //01 00  GetDomen
		$a_01_4 = {4d 61 6b 65 49 74 54 6f 70 57 57 57 } //01 00  MakeItTopWWW
		$a_01_5 = {52 65 70 6c 61 63 65 5f 75 72 6c 57 } //00 00  Replace_urlW
	condition:
		any of ($a_*)
 
}