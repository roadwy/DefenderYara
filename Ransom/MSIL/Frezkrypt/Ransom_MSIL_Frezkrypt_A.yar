
rule Ransom_MSIL_Frezkrypt_A{
	meta:
		description = "Ransom:MSIL/Frezkrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_80_0 = {4a 3a 5c 50 72 6f 67 72 61 6d 73 5c 4a 46 20 52 61 6e 73 6f 6d 77 61 72 65 5c 4a 46 20 52 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 46 20 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //J:\Programs\JF Ransomware\JF Ransomware\obj\Debug\JF Ransomware.pdb  2
		$a_80_1 = {4a 46 20 52 61 6e 73 6f 6d 77 61 72 65 } //JF Ransomware  2
		$a_80_2 = {4a 46 5f 52 61 6e 73 6f 6d 77 61 72 65 } //JF_Ransomware  2
		$a_80_3 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //All of your files have been encrypted!  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=6
 
}