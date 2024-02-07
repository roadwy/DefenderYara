
rule Ransom_Win32_Avaddon_KP{
	meta:
		description = "Ransom:Win32/Avaddon.KP,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 20 3c 73 70 61 6e 3e 41 76 61 64 64 6f 6e } //01 00  Your network has been infected by <span>Avaddon
		$a_01_1 = {68 61 76 65 20 62 65 65 6e 20 3c 62 3e 65 6e 63 72 79 70 74 65 64 } //01 00  have been <b>encrypted
		$a_01_2 = {41 76 61 64 64 6f 6e 20 47 65 6e 65 72 61 6c 20 44 65 63 72 79 70 74 6f 72 } //01 00  Avaddon General Decryptor
		$a_01_3 = {5c 58 4d 65 64 43 6f 6e 5c 62 69 6e 5c 6d 65 64 63 6f 6e } //00 00  \XMedCon\bin\medcon
		$a_01_4 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}