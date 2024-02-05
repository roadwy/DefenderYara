
rule Trojan_Win32_PSWStealer_ACS_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.ACS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 03 00 "
		
	strings :
		$a_80_0 = {73 61 6d 70 2e 64 6c 6c } //samp.dll  03 00 
		$a_80_1 = {57 69 6e 45 78 65 63 } //WinExec  03 00 
		$a_80_2 = {2f 70 61 73 73 77 64 } ///passwd  03 00 
		$a_80_3 = {41 72 69 4d 61 69 6c 53 74 72 3a } //AriMailStr:  03 00 
		$a_80_4 = {68 61 63 6b 6d 6f 64 65 } //hackmode  03 00 
		$a_80_5 = {41 73 68 6f 74 20 53 61 6d 70 } //Ashot Samp  03 00 
		$a_80_6 = {53 4f 46 54 57 41 52 45 5c 53 41 4d 50 } //SOFTWARE\SAMP  03 00 
		$a_80_7 = {61 73 68 6f 74 5f 73 74 } //ashot_st  03 00 
		$a_80_8 = {64 61 74 61 5c 61 63 63 65 73 } //data\acces  03 00 
		$a_80_9 = {41 6e 74 69 53 74 65 61 6c 65 72 42 79 44 61 72 6b 50 31 78 65 6c } //AntiStealerByDarkP1xel  00 00 
	condition:
		any of ($a_*)
 
}