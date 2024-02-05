
rule Backdoor_Win32_Remcos_GA_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0d 00 00 0a 00 "
		
	strings :
		$a_80_0 = {52 65 6d 63 6f 73 } //Remcos  01 00 
		$a_80_1 = {43 6c 6f 73 65 43 61 6d 65 72 61 } //CloseCamera  01 00 
		$a_80_2 = {4f 70 65 6e 43 61 6d 65 72 61 } //OpenCamera  01 00 
		$a_80_3 = {55 70 6c 6f 61 64 } //Upload  01 00 
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 } //Download  01 00 
		$a_80_5 = {5b 45 6e 74 65 72 5d } //[Enter]  01 00 
		$a_80_6 = {53 62 69 65 44 6c 6c 2e 64 6c 6c } //SbieDll.dll  01 00 
		$a_80_7 = {50 52 4f 43 4d 4f 4e 5f 57 49 4e 44 4f 57 5f 43 4c 41 53 53 } //PROCMON_WINDOW_CLASS  01 00 
		$a_80_8 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a } //Remcos_Mutex_Inj  01 00 
		$a_80_9 = {48 41 52 44 57 41 52 45 5c 41 43 50 49 5c 44 53 44 54 5c 56 42 4f 58 5f 5f } //HARDWARE\ACPI\DSDT\VBOX__  01 00 
		$a_80_10 = {6b 65 79 6c 6f 67 } //keylog  01 00 
		$a_80_11 = {5b 4b 65 65 70 41 6c 69 76 65 5d } //[KeepAlive]  01 00 
		$a_80_12 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 2f 76 20 45 6e 61 62 6c 65 4c 55 41 } //\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA  00 00 
	condition:
		any of ($a_*)
 
}