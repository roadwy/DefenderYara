
rule Ransom_Win32_Hardbit_PA_MTB{
	meta:
		description = "Ransom:Win32/Hardbit.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 74 68 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files have been stolen and then encrypted
		$a_01_1 = {75 6e 74 69 6c 20 74 68 65 20 6c 61 73 74 20 66 69 6c 65 20 69 73 20 64 65 63 72 79 70 74 65 64 } //01 00  until the last file is decrypted
		$a_01_2 = {63 79 62 65 72 20 69 6e 73 75 72 61 6e 63 65 20 61 67 61 69 6e 73 74 20 72 61 6e 73 6f 6d 77 61 72 65 20 61 74 74 61 63 6b 73 } //01 00  cyber insurance against ransomware attacks
		$a_01_3 = {67 75 61 72 61 6e 74 65 65 20 74 6f 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 } //01 00  guarantee to restore files
		$a_01_4 = {70 61 79 20 75 73 20 76 69 61 20 42 69 74 63 6f 69 6e } //00 00  pay us via Bitcoin
	condition:
		any of ($a_*)
 
}