
rule Ransom_Win64_Vovalex_MK_MTB{
	meta:
		description = "Ransom:Win64/Vovalex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {76 6f 76 61 6c 65 78 } //01 00  vovalex
		$a_81_1 = {52 45 41 44 4d 45 2e 56 4f 56 41 4c 45 58 2e 74 78 74 } //01 00  README.VOVALEX.txt
		$a_81_2 = {70 68 6f 62 6f 73 } //01 00  phobos
		$a_81_3 = {59 6f 75 72 20 70 68 6f 74 6f 73 2c 20 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 6f 74 68 65 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your photos, documents and other files have been encrypted
		$a_81_4 = {54 68 65 20 64 65 63 72 79 70 74 6f 72 20 63 6f 73 74 73 20 30 2e 35 20 58 4d 52 } //01 00  The decryptor costs 0.5 XMR
		$a_81_5 = {40 63 6f 63 6b 2e 6c 69 } //00 00  @cock.li
		$a_00_6 = {5d 04 00 00 } //fe 69 
	condition:
		any of ($a_*)
 
}