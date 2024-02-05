
rule Trojan_Win32_Potatohttploader_B{
	meta:
		description = "Trojan:Win32/Potatohttploader.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {48 34 73 49 41 41 41 41 41 41 41 45 41 4f 31 59 62 32 77 63 78 52 56 } //H4sIAAAAAAAEAO1Yb2wcxRV  01 00 
		$a_80_1 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_2 = {50 61 73 73 77 6f 72 64 } //Password  01 00 
		$a_80_3 = {68 65 6c 6c 6f 2e 73 74 67 } //hello.stg  01 00 
		$a_80_4 = {53 74 6f 70 2f } //Stop/  01 00 
		$a_80_5 = {5f 48 61 6e 64 6c 65 72 } //_Handler  00 00 
	condition:
		any of ($a_*)
 
}