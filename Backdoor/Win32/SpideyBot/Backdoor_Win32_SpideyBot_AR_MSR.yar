
rule Backdoor_Win32_SpideyBot_AR_MSR{
	meta:
		description = "Backdoor:Win32/SpideyBot.AR!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_02_0 = {44 3a 5c 50 72 6f 6a 65 63 74 73 5c 46 75 63 6b 20 4f 66 66 90 01 03 5c 52 65 6c 65 61 73 65 5c 46 75 63 6b 20 4f 66 66 90 01 03 2e 70 64 62 90 00 } //01 00 
		$a_01_1 = {62 57 39 6b 64 57 78 6c 4c 6d 56 34 63 47 39 79 64 48 4d 67 50 53 42 79 5a 58 46 31 61 58 4a 6c 4b 43 63 75 4c 32 4e 76 63 6d 55 75 59 58 4e 68 63 69 63 70 4f 77 3d 3d } //00 00  bW9kdWxlLmV4cG9ydHMgPSByZXF1aXJlKCcuL2NvcmUuYXNhcicpOw==
	condition:
		any of ($a_*)
 
}