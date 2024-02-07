
rule Trojan_Win32_Farfli_DAU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {53 56 57 89 4d e4 89 65 f0 6a 00 68 90 01 02 40 00 ff 15 90 01 02 40 00 6a 00 6a 00 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 e8 90 01 02 90 01 02 6a 00 6a 00 6a 00 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 ff 15 90 00 } //02 00 
		$a_03_1 = {55 8b ec 83 ec 08 53 56 57 6a 00 6a 00 68 90 01 02 40 00 68 90 01 02 40 00 6a 00 e8 90 01 02 90 01 02 6a 00 6a 00 6a 04 6a 00 6a 00 68 00 00 00 80 68 90 01 02 40 00 ff 15 90 00 } //01 00 
		$a_01_2 = {8b f8 6a 40 68 00 10 00 00 57 6a 00 ff 15 } //01 00 
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 50 72 6f 67 72 61 6d 44 61 74 61 2e 74 78 74 } //00 00  C:\ProgramData\ProgramData.txt
	condition:
		any of ($a_*)
 
}