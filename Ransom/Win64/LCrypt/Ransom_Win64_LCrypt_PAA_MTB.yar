
rule Ransom_Win64_LCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win64/LCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 6c 63 72 79 5f 65 6e 63 } //01 00  _lcry_enc
		$a_01_1 = {4f 6f 70 73 2c 44 61 74 61 20 6c 6f 73 74 21 } //01 00  Oops,Data lost!
		$a_01_2 = {42 75 74 20 79 6f 75 20 63 6c 6f 73 65 64 20 4c 43 52 59 21 } //01 00  But you closed LCRY!
		$a_01_3 = {66 31 6c 65 73 20 68 61 76 65 20 62 33 33 6e 20 65 6e 63 72 79 70 74 33 64 20 62 79 20 6d 33 } //01 00  f1les have b33n encrypt3d by m3
		$a_01_4 = {59 6f 75 72 20 41 45 53 20 6b 65 79 20 69 73 20 69 6e 20 4c 43 52 59 27 73 20 6d 65 6d 6f 72 79 2e } //00 00  Your AES key is in LCRY's memory.
	condition:
		any of ($a_*)
 
}