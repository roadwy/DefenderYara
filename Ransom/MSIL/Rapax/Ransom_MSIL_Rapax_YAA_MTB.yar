
rule Ransom_MSIL_Rapax_YAA_MTB{
	meta:
		description = "Ransom:MSIL/Rapax.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 61 70 61 78 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 Rapax Ransomware
		$a_01_1 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
		$a_01_2 = {44 45 43 52 59 50 54 49 4f 4e 20 4b 45 59 } //1 DECRYPTION KEY
		$a_01_3 = {50 41 59 20 41 20 52 41 4e 53 4f 4d } //1 PAY A RANSOM
		$a_01_4 = {50 75 72 63 68 61 73 65 20 42 69 74 63 6f 69 6e } //1 Purchase Bitcoin
		$a_01_5 = {72 65 73 74 6f 72 65 20 61 63 63 65 73 73 20 74 6f 20 79 6f 75 72 20 66 69 6c 65 73 } //1 restore access to your files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}