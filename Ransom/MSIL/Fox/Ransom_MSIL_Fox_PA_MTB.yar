
rule Ransom_MSIL_Fox_PA_MTB{
	meta:
		description = "Ransom:MSIL/Fox.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 61 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d } //01 00  All your files have been encrypted due to a security problem
		$a_01_1 = {3a 5c 55 73 65 72 73 5c 46 6f 78 5c 44 65 73 6b 74 6f 70 5c 46 6f 78 5c } //01 00  :\Users\Fox\Desktop\Fox\
		$a_01_2 = {52 00 61 00 6e 00 20 00 43 00 72 00 69 00 70 00 72 00 3a 00 } //01 00  Ran Cripr:
		$a_01_3 = {5b 00 46 00 6f 00 78 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 40 00 70 00 72 00 6f 00 74 00 6f 00 6e 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 5d 00 2e 00 76 00 65 00 6e 00 64 00 65 00 74 00 74 00 61 00 } //00 00  [Foxdecrypt@protonmail.com].vendetta
	condition:
		any of ($a_*)
 
}