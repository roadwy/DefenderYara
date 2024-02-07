
rule Ransom_Win64_Gocoder_P{
	meta:
		description = "Ransom:Win64/Gocoder.P,SIGNATURE_TYPE_PEHSTR,0f 00 03 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {48 65 6c 6c 6f 21 20 59 6f 75 72 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 6f 6e 6c 79 20 49 20 63 61 6e 20 64 65 63 72 79 70 74 20 74 68 65 6d } //01 00  Hello! Your all your files are encrypted and only I can decrypt them
		$a_01_1 = {64 6f 63 74 6f 72 36 36 36 40 6d 61 69 6c 2e 66 72 } //01 00  doctor666@mail.fr
		$a_01_2 = {6d 69 6d 65 2e 70 65 72 63 65 6e 74 48 65 78 55 6e 65 73 63 61 70 65 } //05 00  mime.percentHexUnescape
		$a_01_3 = {59 6f 75 20 63 61 6e 20 62 65 20 61 20 76 69 63 74 69 6d 20 6f 66 20 66 72 61 75 64 } //05 00  You can be a victim of fraud
		$a_01_4 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2e 20 59 6f 75 20 6d 61 79 20 68 61 76 65 20 70 65 72 6d 61 6e 65 6e 74 20 64 61 74 61 20 6c 6f 73 73 } //01 00  Do not rename encrypted files. You may have permanent data loss
		$a_01_5 = {57 72 69 74 65 20 6d 65 20 69 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 74 75 72 6e 20 79 6f 75 72 20 66 69 6c 65 73 20 2d 20 49 20 63 61 6e 20 64 6f 20 69 74 20 76 65 72 79 20 71 75 69 63 6b 6c 79 } //00 00  Write me if you want to return your files - I can do it very quickly
		$a_01_6 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}