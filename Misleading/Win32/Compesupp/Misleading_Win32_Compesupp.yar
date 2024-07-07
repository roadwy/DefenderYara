
rule Misleading_Win32_Compesupp{
	meta:
		description = "Misleading:Win32/Compesupp,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 77 74 6f 6f 6c 62 6f 78 2e 64 6c 6c } //1 rwtoolbox.dll
		$a_01_1 = {3c 43 6f 6d 6d 61 6e 64 3e 72 65 67 77 69 7a 2e 65 78 65 3c 2f 43 6f 6d 6d 61 6e 64 3e } //1 <Command>regwiz.exe</Command>
		$a_01_2 = {3c 41 75 74 68 6f 72 3e 65 53 75 70 70 6f 72 74 2e 63 6f 6d 2c 20 49 6e 63 3c 2f 41 75 74 68 6f 72 3e } //1 <Author>eSupport.com, Inc</Author>
		$a_01_3 = {52 65 67 69 73 74 72 79 57 69 7a 61 72 64 4d 75 74 65 78 } //1 RegistryWizardMutex
		$a_01_4 = {52 65 67 69 73 74 72 79 57 69 7a 61 72 64 2e 52 65 73 74 6f 72 65 2e 43 6f 6d 6d 61 6e 64 } //1 RegistryWizard.Restore.Command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}