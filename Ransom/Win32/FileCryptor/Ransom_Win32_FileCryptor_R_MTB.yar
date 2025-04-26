
rule Ransom_Win32_FileCryptor_R_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {50 72 6f 63 65 73 73 68 61 63 6b 65 72 } //1 Processhacker
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_2 = {4e 4f 20 54 52 41 54 45 53 20 44 45 20 42 4f 52 52 41 52 20 45 4c 20 52 41 4e 53 4f 4d 57 41 52 45 } //1 NO TRATES DE BORRAR EL RANSOMWARE
		$a_81_3 = {4e 4f 20 54 52 41 54 45 53 20 44 45 20 41 42 52 49 52 20 41 52 43 48 49 56 4f 53 20 45 4e 43 52 59 50 54 41 44 4f 53 } //1 NO TRATES DE ABRIR ARCHIVOS ENCRYPTADOS
		$a_81_4 = {45 53 54 45 20 41 52 43 48 49 56 4f 20 45 53 54 41 20 4d 55 59 20 42 49 45 4e 20 45 4e 43 52 59 50 54 41 44 4f 20 4e 4f 20 54 52 41 54 45 53 } //1 ESTE ARCHIVO ESTA MUY BIEN ENCRYPTADO NO TRATES
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}