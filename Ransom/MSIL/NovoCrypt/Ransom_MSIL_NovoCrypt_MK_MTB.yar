
rule Ransom_MSIL_NovoCrypt_MK_MTB{
	meta:
		description = "Ransom:MSIL/NovoCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 77 61 72 65 } //Ransomware  0a 00 
		$a_80_1 = {52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 } //Ransomware.Properties  0a 00 
		$a_80_2 = {79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //your important files have been encrypted  0a 00 
		$a_80_3 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 70 65 72 6d 61 6d 65 6e 74 6c 79 20 73 68 72 65 64 64 65 64 } //your files will be permamently shredded  00 00 
	condition:
		any of ($a_*)
 
}