
rule Ransom_Win32_Egregor_SU_MTB{
	meta:
		description = "Ransom:Win32/Egregor.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00  DllInstall
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_81_3 = {43 72 79 70 74 33 32 2e 64 6c 6c } //01 00  Crypt32.dll
		$a_81_4 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //01 00  CryptStringToBinaryA
		$a_81_5 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //05 00  expand 32-byte kexpand 16-byte k
		$a_81_6 = {5c 66 61 73 6d 5c 49 4e 43 4c 55 44 45 5c 41 50 49 5c 66 61 73 6d 2e 70 64 62 } //05 00  \fasm\INCLUDE\API\fasm.pdb
		$a_81_7 = {3a 5c 68 65 68 65 5c 63 79 62 65 72 63 6f 6d 2e 70 64 62 } //05 00  :\hehe\cybercom.pdb
		$a_81_8 = {3a 5c 73 63 5c 70 5c 73 65 64 2e 70 64 62 } //05 00  :\sc\p\sed.pdb
		$a_81_9 = {3a 5c 64 65 66 61 75 6c 74 6c 6f 67 5c 69 6e 73 74 61 6c 6c 61 74 6f 72 5c 64 65 62 75 67 5c 64 73 73 2e 70 64 62 } //00 00  :\defaultlog\installator\debug\dss.pdb
	condition:
		any of ($a_*)
 
}