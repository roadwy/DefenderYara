
rule Ransom_Win64_LockBit_M{
	meta:
		description = "Ransom:Win64/LockBit.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 08 32 4c 04 20 88 0b 48 ff c0 eb e2 } //1
		$a_03_1 = {44 0f b6 ca 45 69 c9 01 01 01 ?? 49 83 f8 07 76 0d } //1
		$a_00_2 = {5b 00 25 00 64 00 5d 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //-1 [%d] Decrypted:
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}