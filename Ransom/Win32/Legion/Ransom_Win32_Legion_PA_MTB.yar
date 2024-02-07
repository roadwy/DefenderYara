
rule Ransom_Win32_Legion_PA_MTB{
	meta:
		description = "Ransom:Win32/Legion.PA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 65 00 67 00 69 00 6f 00 6e 00 5f 00 5f 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  Legion__Ransomware
		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 2d 00 4d 00 65 00 2d 00 4e 00 6f 00 77 00 2e 00 74 00 78 00 74 00 } //01 00  \READ-Me-Now.txt
		$a_01_2 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 66 00 61 00 72 00 73 00 68 00 61 00 64 00 } //01 00  \Desktop\farshad
		$a_01_3 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 } //01 00  bytesToBeEncr
		$a_01_4 = {65 6e 63 72 79 70 74 64 69 72 } //01 00  encryptdir
		$a_01_5 = {70 61 73 73 77 6f 72 64 42 79 74 65 73 } //00 00  passwordBytes
	condition:
		any of ($a_*)
 
}