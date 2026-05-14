
rule Ransom_Win64_ContiCrypt_PAHR_MTB{
	meta:
		description = "Ransom:Win64/ContiCrypt.PAHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 69 74 74 6f 67 72 61 66 69 61 20 63 6f 6d 70 6c 65 74 61 74 61 } //2 Crittografia completata
		$a_01_1 = {49 6e 69 7a 69 6f 20 73 63 61 6e 73 69 6f 6e 65 20 65 20 63 72 69 70 74 61 7a 69 6f 6e 65 } //2 Inizio scansione e criptazione
		$a_01_2 = {63 72 65 61 7a 69 6f 6e 65 20 74 68 72 65 61 64 20 73 68 65 6c 6c 63 6f 64 65 } //1 creazione thread shellcode
		$a_01_3 = {45 72 72 6f 72 65 20 6e 65 6c 6c 27 61 67 67 69 75 73 74 61 72 65 20 69 20 70 72 69 76 69 6c 65 67 69 } //1 Errore nell'aggiustare i privilegi
		$a_01_4 = {45 72 72 6f 72 65 20 64 75 72 61 6e 74 65 20 6c 61 20 63 72 65 61 7a 69 6f 6e 65 20 64 65 6c 6c 6f 20 73 6e 61 70 73 68 6f 74 20 64 69 20 70 72 6f 63 65 73 73 6f } //1 Errore durante la creazione dello snapshot di processo
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}