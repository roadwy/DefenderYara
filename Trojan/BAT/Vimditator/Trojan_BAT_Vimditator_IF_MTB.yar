
rule Trojan_BAT_Vimditator_IF_MTB{
	meta:
		description = "Trojan:BAT/Vimditator.IF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {55 73 65 72 73 5c 57 65 6c 63 6f 6d 65 5c 44 6f 63 75 6d 65 6e 74 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 30 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 30 5c 62 69 6e 5c 44 65 62 75 67 5c 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 50 41 47 56 2e 70 64 62 } //1 Users\Welcome\Documents\WindowsFormsApp10\WindowsFormsApp10\bin\Debug\CryptoObfuscator_Output\PAGV.pdb
		$a_01_1 = {50 00 41 00 47 00 56 00 2e 00 65 00 78 00 65 00 } //1 PAGV.exe
		$a_81_2 = {50 41 47 56 26 26 } //1 PAGV&&
		$a_81_3 = {50 41 47 56 2e 50 72 6f 70 65 72 74 69 65 73 } //1 PAGV.Properties
		$a_81_4 = {50 72 6f 63 65 73 73 48 61 6e 64 6c 65 } //1 ProcessHandle
		$a_81_5 = {50 72 6f 63 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6c 61 73 73 } //1 ProcessInformationClass
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}