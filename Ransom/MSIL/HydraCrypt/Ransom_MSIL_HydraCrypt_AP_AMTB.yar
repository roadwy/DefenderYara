
rule Ransom_MSIL_HydraCrypt_AP_AMTB{
	meta:
		description = "Ransom:MSIL/HydraCrypt.AP!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {41 74 74 65 6d 70 74 69 6e 67 20 41 4d 53 49 20 62 79 70 61 73 73 } //Attempting AMSI bypass  1
		$a_80_1 = {41 74 74 65 6d 70 74 69 6e 67 20 45 54 57 20 70 61 74 63 68 69 6e 67 } //Attempting ETW patching  1
		$a_80_2 = {44 72 6f 70 70 69 6e 67 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 20 61 74 } //Dropping ransom note at  1
		$a_80_3 = {52 45 41 44 4d 45 5f 44 45 43 52 59 50 54 2e 74 78 74 } //README_DECRYPT.txt  1
		$a_80_4 = {52 44 50 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 77 69 74 68 20 73 74 6f 6c 65 6e 20 63 72 65 64 65 6e 74 69 61 6c 73 } //RDP connections with stolen credentials  1
		$a_80_5 = {52 61 6e 73 6f 6d 20 6e 6f 74 65 20 6e 6f 74 20 77 72 69 74 74 65 6e } //Ransom note not written  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}