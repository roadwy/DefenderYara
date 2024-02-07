
rule Ransom_Win32_Lizard_PAA_MTB{
	meta:
		description = "Ransom:Win32/Lizard.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 53 45 52 56 45 52 2f 43 4f 4d 50 55 54 45 52 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 75 73 } //01 00  Your SERVER/COMPUTER is encrypted by us
		$a_01_1 = {63 72 79 70 74 6f 70 70 2d 43 52 59 50 54 4f 50 50 } //01 00  cryptopp-CRYPTOPP
		$a_01_2 = {45 4e 43 52 59 50 54 45 52 40 73 65 72 76 65 72 } //01 00  ENCRYPTER@server
		$a_01_3 = {5c 23 52 65 61 64 54 68 69 73 2e 48 54 41 } //01 00  \#ReadThis.HTA
		$a_01_4 = {4b 69 6e 67 20 4f 66 20 52 61 6e 73 6f 6d } //01 00  King Of Ransom
		$a_01_5 = {6b 65 79 2e 74 78 74 2e 4c 49 5a 41 52 44 } //00 00  key.txt.LIZARD
	condition:
		any of ($a_*)
 
}