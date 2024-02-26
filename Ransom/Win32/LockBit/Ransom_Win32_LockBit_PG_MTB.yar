
rule Ransom_Win32_LockBit_PG_MTB{
	meta:
		description = "Ransom:Win32/LockBit.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 63 00 6b 00 42 00 69 00 74 00 2e 00 4a 00 50 00 47 00 } //01 00  LockBit.JPG
		$a_01_1 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 2e } //01 00  Your data is stolen and encrypted.
		$a_01_2 = {4c 6f 63 6b 42 69 74 20 33 2e 30 20 74 68 65 20 77 6f 72 6c 64 27 73 20 66 61 73 74 65 73 74 20 61 6e 64 20 6d 6f 73 74 20 73 74 61 62 6c 65 20 72 61 6e 73 6f 6d 77 61 72 65 } //00 00  LockBit 3.0 the world's fastest and most stable ransomware
	condition:
		any of ($a_*)
 
}