
rule Virus_Win32_Viking_SA_MTB{
	meta:
		description = "Virus:Win32/Viking.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c 90 02 10 2e 65 78 65 22 20 67 6f 74 6f 20 74 72 79 31 90 00 } //01 00 
		$a_02_1 = {72 65 6e 20 22 43 3a 5c 90 02 10 2e 65 78 65 2e 65 78 65 22 20 22 90 02 10 2e 65 78 65 22 90 00 } //01 00 
		$a_02_2 = {69 66 20 65 78 69 73 74 20 22 43 3a 5c 90 02 10 2e 65 78 65 2e 65 78 65 22 20 67 6f 74 6f 20 74 72 79 32 90 00 } //01 00 
		$a_00_3 = {64 65 6c 20 22 43 3a 5c 54 45 4d 50 5c 24 24 61 62 32 38 39 30 2e 62 61 74 22 } //00 00  del "C:\TEMP\$$ab2890.bat"
	condition:
		any of ($a_*)
 
}