
rule Ransom_MSIL_Filecoder_SWA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 4f 53 55 2e 70 64 62 } //2 NOSU.pdb
		$a_01_1 = {4e 4f 53 55 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 NOSU.Resources.resources
		$a_01_2 = {54 00 68 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 77 00 61 00 73 00 20 00 69 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 74 00 68 00 65 00 20 00 4e 00 4f 00 53 00 55 00 20 00 76 00 69 00 72 00 75 00 73 00 } //1 The system was infected with the NOSU virus
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 DisableAntiSpyware
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Ransom_MSIL_Filecoder_SWA_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6e 63 72 79 70 74 41 6c 6c 46 69 6c 65 73 } //2 EncryptAllFiles
		$a_01_1 = {24 61 32 66 39 66 33 38 64 2d 65 33 32 39 2d 34 30 36 66 2d 62 65 30 32 2d 39 34 63 39 34 30 64 35 39 65 33 62 } //1 $a2f9f38d-e329-406f-be02-94c940d59e3b
		$a_01_2 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 67 00 6f 00 74 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 } //1 All of your files got encrypted!
		$a_01_3 = {63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 62 00 6f 00 74 00 2e 00 70 00 64 00 62 00 2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 } //1 costura.telegram.bot.pdb.compressed
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule Ransom_MSIL_Filecoder_SWA_MTB_3{
	meta:
		description = "Ransom:MSIL/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 49 4c 4c 5f 41 50 50 53 5f 45 4e 43 52 59 50 54 5f 41 47 41 49 4e } //2 KILL_APPS_ENCRYPT_AGAIN
		$a_00_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 73 00 74 00 6f 00 6c 00 65 00 6e 00 20 00 61 00 6e 00 64 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All your files are stolen and encrypted
		$a_01_3 = {45 4e 43 52 59 50 54 5f 44 41 54 41 } //1 ENCRYPT_DATA
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}