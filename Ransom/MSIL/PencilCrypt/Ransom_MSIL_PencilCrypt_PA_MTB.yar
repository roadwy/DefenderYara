
rule Ransom_MSIL_PencilCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/PencilCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 65 00 73 00 5c 00 62 00 67 00 2e 00 6a 00 70 00 67 00 } //01 00  \res\bg.jpg
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 65 00 6e 00 63 00 69 00 6c 00 43 00 72 00 79 00 } //01 00  SOFTWARE\PencilCry
		$a_01_2 = {2e 00 70 00 65 00 6e 00 63 00 69 00 6c 00 63 00 72 00 79 00 } //01 00  .pencilcry
		$a_01_3 = {79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //00 00  your files have been encrypted!
	condition:
		any of ($a_*)
 
}