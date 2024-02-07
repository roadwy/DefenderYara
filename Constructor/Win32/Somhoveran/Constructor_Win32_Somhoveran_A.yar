
rule Constructor_Win32_Somhoveran_A{
	meta:
		description = "Constructor:Win32/Somhoveran.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 61 72 6e 69 6e 67 21 20 57 69 6e 64 6f 77 73 20 42 6c 6f 63 6b 65 64 21 } //01 00  Warning! Windows Blocked!
		$a_01_1 = {43 68 61 6e 65 6c 6c 3a 20 20 20 20 20 20 20 79 6f 75 74 75 62 65 2e 63 6f 6d 2f 75 73 65 72 2f 4d 72 44 69 67 69 74 61 6c 49 6e 66 65 63 74 69 6f 6e } //01 00  Chanell:       youtube.com/user/MrDigitalInfection
		$a_01_2 = {54 72 6f 6a 61 6e 2e 65 78 65 } //00 00  Trojan.exe
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}