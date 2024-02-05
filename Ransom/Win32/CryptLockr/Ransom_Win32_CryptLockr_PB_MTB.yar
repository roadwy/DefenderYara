
rule Ransom_Win32_CryptLockr_PB_MTB{
	meta:
		description = "Ransom:Win32/CryptLockr.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 69 70 68 65 72 2e 70 73 6d 31 } //01 00 
		$a_01_1 = {24 68 6f 6d 65 5c 44 65 73 6b 74 6f 70 5c 52 65 61 64 6d 65 5f 6e 6f 77 2e 74 78 74 } //01 00 
		$a_01_2 = {59 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_01_3 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 4d 6f 64 75 6c 65 73 5c 43 69 70 68 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}