
rule Trojan_Win64_Stealer_PADB_MTB{
	meta:
		description = "Trojan:Win64/Stealer.PADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 4d 70 48 65 61 64 6c 65 73 73 52 75 6e 2e 65 78 65 } //01 00  C:\Program Files (x86)\Windows Defender\MpHeadlessRun.exe
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 61 64 64 65 64 20 74 6f 20 73 74 61 72 74 75 70 20 73 75 63 63 65 73 73 66 75 6c 6c 79 2e } //01 00  Application added to startup successfully.
		$a_01_2 = {4d 61 6b 65 20 73 75 72 65 20 74 6f 20 72 75 6e 20 74 68 65 20 70 72 6f 67 72 61 6d 20 77 69 74 68 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 20 70 72 69 76 69 6c 65 67 65 73 } //01 00  Make sure to run the program with administrator privileges
		$a_01_3 = {73 74 65 61 6c 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 74 65 61 6c 65 72 2e 70 64 62 } //00 00  stealer\x64\Release\stealer.pdb
	condition:
		any of ($a_*)
 
}