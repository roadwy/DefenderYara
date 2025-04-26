
rule Ransom_Win32_Avaddon_AA_MTB{
	meta:
		description = "Ransom:Win32/Avaddon.AA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 20 3c 73 70 61 6e 3e 41 76 61 64 64 6f 6e } //1 Your network has been infected by <span>Avaddon
		$a_01_1 = {68 61 76 65 20 62 65 65 6e 20 3c 62 3e 65 6e 63 72 79 70 74 65 64 } //1 have been <b>encrypted
		$a_01_2 = {41 76 61 64 64 6f 6e 20 47 65 6e 65 72 61 6c 20 44 65 63 72 79 70 74 6f 72 } //1 Avaddon General Decryptor
		$a_01_3 = {31 5c 42 49 4e 5c 67 6d 2e 65 78 65 } //1 1\BIN\gm.exe
		$a_01_4 = {5c 58 4d 65 64 43 6f 6e 5c 62 69 6e 5c 6d 65 64 63 6f 6e 2e 65 78 65 } //1 \XMedCon\bin\medcon.exe
		$a_01_5 = {3c 70 3e 44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 72 65 63 6f 76 65 72 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 21 3c 2f 70 3e } //1 <p>Do not try to recover files yourself!</p>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}