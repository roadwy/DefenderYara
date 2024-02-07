
rule Trojan_Win32_Temperifie_A{
	meta:
		description = "Trojan:Win32/Temperifie.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {30 78 30 30 33 30 00 31 30 33 34 00 31 30 33 39 00 31 30 32 38 00 31 32 35 36 } //02 00 
		$a_01_1 = {70 65 72 6d 69 74 65 2e 69 6e 66 6f 2f } //01 00  permite.info/
		$a_01_2 = {2f 68 76 73 62 74 6e 2e 65 78 65 } //01 00  /hvsbtn.exe
		$a_01_3 = {2f 6e 32 73 74 6e 2e 65 78 65 } //01 00  /n2stn.exe
		$a_01_4 = {2f 68 6b 6d 73 67 72 2e 65 78 65 } //00 00  /hkmsgr.exe
	condition:
		any of ($a_*)
 
}