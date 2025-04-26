
rule Ransom_MSIL_NitroCrypt_MK_MTB{
	meta:
		description = "Ransom:MSIL/NitroCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 6f 64 6f 73 20 73 75 73 20 64 6f 63 75 6d 65 6e 74 6f 73 20 69 6d 70 6f 72 74 61 6e 74 65 73 20 73 65 20 68 61 6e 20 62 6c 6f 71 75 65 61 64 6f 20 79 20 73 65 20 68 61 6e 20 63 69 66 72 61 64 6f 20 63 6f 6e 20 41 45 53 } //1 Todos sus documentos importantes se han bloqueado y se han cifrado con AES
		$a_81_1 = {4f 68 2c 20 6e 6f 21 20 53 75 73 20 61 72 63 68 69 76 6f 73 20 73 65 20 68 61 6e 20 63 69 66 72 61 64 6f } //1 Oh, no! Sus archivos se han cifrado
		$a_81_2 = {49 6e 69 63 69 61 6e 64 6f 20 65 6c 20 63 69 66 72 61 64 6f 20 64 65 20 61 72 63 68 69 76 6f 73 } //1 Iniciando el cifrado de archivos
		$a_81_3 = {6d 65 72 6f 20 74 6f 74 61 6c 20 64 65 20 61 72 63 68 69 76 6f 73 20 63 69 66 72 61 64 6f 73 3a } //1 mero total de archivos cifrados:
		$a_81_4 = {6d 6f 20 6f 62 74 65 6e 67 6f 20 6c 61 20 63 6c 61 76 65 20 64 65 20 64 65 73 63 69 66 72 61 64 6f 3f } //1 mo obtengo la clave de descifrado?
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}