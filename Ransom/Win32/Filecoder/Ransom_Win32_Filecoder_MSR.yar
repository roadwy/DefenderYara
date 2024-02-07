
rule Ransom_Win32_Filecoder_MSR{
	meta:
		description = "Ransom:Win32/Filecoder!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 49 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //01 00  Decrypt Instructions.txt
		$a_01_1 = {44 65 61 74 68 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 73 73 76 63 68 6f 73 74 2e 70 64 62 } //01 00  Death\obj\Release\ssvchost.pdb
		$a_00_2 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //00 00  All of your files are encrypted
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_MSR_2{
	meta:
		description = "Ransom:Win32/Filecoder!MSR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 65 00 72 00 72 00 79 00 5f 00 67 00 6c 00 61 00 6e 00 76 00 69 00 6c 00 6c 00 65 00 5f 00 64 00 61 00 74 00 61 00 40 00 61 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  jerry_glanville_data@aol.com
		$a_01_1 = {48 00 4f 00 57 00 5f 00 54 00 4f 00 5f 00 52 00 45 00 43 00 4f 00 56 00 45 00 52 00 59 00 5f 00 46 00 49 00 4c 00 45 00 53 00 2e 00 74 00 78 00 74 00 } //01 00  HOW_TO_RECOVERY_FILES.txt
		$a_01_2 = {44 00 72 00 2e 00 57 00 65 00 62 00 } //01 00  Dr.Web
		$a_01_3 = {4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 20 00 4c 00 61 00 62 00 } //00 00  Kaspersky Lab
	condition:
		any of ($a_*)
 
}