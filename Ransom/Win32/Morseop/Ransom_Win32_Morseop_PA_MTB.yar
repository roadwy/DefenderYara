
rule Ransom_Win32_Morseop_PA_MTB{
	meta:
		description = "Ransom:Win32/Morseop.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 44 69 73 6b 28 25 77 73 29 20 44 4f 4e 45 } //01 00  EncryptDisk(%ws) DONE
		$a_01_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //01 00  ransomware.exe
		$a_01_2 = {21 00 21 00 5f 00 46 00 49 00 4c 00 45 00 53 00 5f 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 5f 00 2e 00 74 00 78 00 74 00 } //01 00  !!_FILES_ENCRYPTED_.txt
		$a_01_3 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 70 65 6e 65 74 72 61 74 65 64 } //01 00  Your network has been penetrated
		$a_01_4 = {72 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //01 00  ransomware.pdb
		$a_01_5 = {43 79 6e 65 74 20 52 61 6e 73 6f 6d 20 50 72 6f 74 65 63 74 69 6f 6e 28 44 4f 4e 27 54 20 44 45 4c 45 54 45 29 } //00 00  Cynet Ransom Protection(DON'T DELETE)
		$a_00_6 = {5d 04 00 } //00 d0 
	condition:
		any of ($a_*)
 
}