
rule Misleading_Win32_Compesupp{
	meta:
		description = "Misleading:Win32/Compesupp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 77 74 6f 6f 6c 62 6f 78 2e 64 6c 6c } //01 00  rwtoolbox.dll
		$a_01_1 = {3c 43 6f 6d 6d 61 6e 64 3e 72 65 67 77 69 7a 2e 65 78 65 3c 2f 43 6f 6d 6d 61 6e 64 3e } //01 00  <Command>regwiz.exe</Command>
		$a_01_2 = {3c 41 75 74 68 6f 72 3e 65 53 75 70 70 6f 72 74 2e 63 6f 6d 2c 20 49 6e 63 3c 2f 41 75 74 68 6f 72 3e } //01 00  <Author>eSupport.com, Inc</Author>
		$a_01_3 = {52 65 67 69 73 74 72 79 57 69 7a 61 72 64 4d 75 74 65 78 } //01 00  RegistryWizardMutex
		$a_01_4 = {52 65 67 69 73 74 72 79 57 69 7a 61 72 64 2e 52 65 73 74 6f 72 65 2e 43 6f 6d 6d 61 6e 64 } //00 00  RegistryWizard.Restore.Command
		$a_00_5 = {60 1e } //00 00  Ṡ
	condition:
		any of ($a_*)
 
}