
rule Ransom_Win32_Filecoder_PAGS_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 4f 43 4b 49 46 59 20 52 31 20 52 41 4e 53 4f 4d 45 57 41 52 45 21 } //3 LOCKIFY R1 RANSOMEWARE!
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 73 2c 20 64 61 74 61 73 2c 20 46 69 6c 65 73 2c 20 44 6f 63 75 6d 65 6e 74 73 2c 20 50 69 63 74 75 72 65 73 2c 20 4c 6f 67 69 6e 73 2c 20 56 69 64 65 6f 73 20 65 74 63 2e 2e 20 61 6c 6c 20 77 65 72 65 20 63 6f 6d 70 6c 65 74 65 6c 79 20 45 4e 43 52 59 50 54 45 44 } //2 All your personal informations, datas, Files, Documents, Pictures, Logins, Videos etc.. all were completely ENCRYPTED
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}