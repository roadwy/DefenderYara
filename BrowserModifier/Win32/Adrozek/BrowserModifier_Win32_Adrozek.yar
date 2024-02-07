
rule BrowserModifier_Win32_Adrozek{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {84 d2 75 33 80 39 4c 75 2e 80 79 01 6f 75 28 80 fb 78 75 23 80 79 0d 41 75 1d } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Adrozek_2{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Adrozek_3{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 2e 00 61 00 76 00 61 00 73 00 74 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Adrozek_4{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 30 35 42 38 30 44 45 2d 39 35 46 31 2d 31 31 44 30 2d 42 30 41 30 2d 30 30 41 41 30 30 42 44 43 42 35 43 } //01 00  105B80DE-95F1-11D0-B0A0-00AA00BDCB5C
		$a_01_1 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 43 00 4c 00 53 00 49 00 44 00 5c 00 7b 00 34 00 37 00 32 00 30 00 38 00 33 00 42 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule BrowserModifier_Win32_Adrozek_5{
	meta:
		description = "BrowserModifier:Win32/Adrozek,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 69 00 6e 00 69 00 6e 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 00 00 44 62 67 50 72 69 6e 74 00 00 00 00 } //01 00 
		$a_00_1 = {46 00 6f 00 6c 00 64 00 65 00 72 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 45 00 78 00 5c 00 43 00 6f 00 6e 00 74 00 65 00 78 00 74 00 4d 00 65 00 6e 00 75 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 73 00 5c 00 61 00 76 00 61 00 73 00 74 00 } //00 00  Folder\ShellEx\ContextMenuHandlers\avast
	condition:
		any of ($a_*)
 
}