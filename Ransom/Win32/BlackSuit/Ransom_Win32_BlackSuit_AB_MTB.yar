
rule Ransom_Win32_BlackSuit_AB_MTB{
	meta:
		description = "Ransom:Win32/BlackSuit.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 74 6f 72 74 69 6f 6e 65 72 20 6e 61 6d 65 64 20 20 42 6c 61 63 6b 53 75 69 74 20 68 61 73 20 61 74 74 61 63 6b 65 64 20 79 6f 75 72 20 73 79 73 74 65 6d } //01 00  Extortioner named  BlackSuit has attacked your system
		$a_01_1 = {61 6c 6c 20 79 6f 75 72 20 65 73 73 65 6e 74 69 61 6c 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  all your essential files were encrypted
		$a_01_2 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //01 00  Delete Shadows /All /Quiet
		$a_01_3 = {2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 76 00 61 00 6c 00 75 00 65 00 20 00 7b 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 7d 00 20 00 73 00 61 00 66 00 65 00 62 00 6f 00 6f 00 74 00 } //01 00  /deletevalue {current} safeboot
		$a_01_4 = {65 6e 63 72 79 70 74 6f 72 5c 52 65 6c 65 61 73 65 5c 65 6e 63 72 79 70 74 6f 72 2e 70 64 62 } //00 00  encryptor\Release\encryptor.pdb
	condition:
		any of ($a_*)
 
}