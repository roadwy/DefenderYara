
rule Ransom_MSIL_FileCoder_B_AMTB{
	meta:
		description = "Ransom:MSIL/FileCoder.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {79 6f 75 20 62 65 63 61 6d 65 20 61 20 76 69 63 74 69 6d 20 6f 66 20 73 65 72 69 61 6c 20 72 61 6e 73 6f 6d 77 61 72 65 21 } //you became a victim of serial ransomware!  1
		$a_80_1 = {61 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 61 20 76 65 72 79 20 73 74 72 6f 6e 67 20 6b 65 79 21 } //any of your files are encrypted by a very strong key!  1
		$a_80_2 = {6f 6e 6c 79 20 77 61 79 20 74 6f 20 67 65 74 20 79 6f 75 72 20 64 61 74 61 20 69 73 20 74 6f 20 70 61 79 20 36 38 24 20 77 6f 74 68 20 6f 66 20 62 69 74 63 6f 69 6e 21 } //only way to get your data is to pay 68$ woth of bitcoin!  1
		$a_80_3 = {41 52 45 20 59 4f 55 20 53 55 52 45 20 41 42 4f 55 54 20 59 4f 55 20 4e 45 45 44 20 54 4f 20 42 52 49 43 4b 20 54 48 49 53 20 50 43 3f } //ARE YOU SURE ABOUT YOU NEED TO BRICK THIS PC?  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}