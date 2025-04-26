
rule Ransom_Win32_LockBit_K{
	meta:
		description = "Ransom:Win32/LockBit.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 65 72 73 69 6f 6e 3a 20 4c 6f 63 6b 42 69 74 47 72 65 65 6e } //1 Version: LockBitGreen
		$a_03_1 = {7e 7e 7e 20 59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 61 74 74 61 63 ?? 65 64 20 62 79 20 4c 6f 63 6b 42 69 74 20 34 } //1
		$a_00_2 = {5b 00 25 00 64 00 5d 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //-1 [%d] Decrypted:
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}