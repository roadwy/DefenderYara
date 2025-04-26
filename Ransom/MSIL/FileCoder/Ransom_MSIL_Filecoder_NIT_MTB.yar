
rule Ransom_MSIL_Filecoder_NIT_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6e 63 72 79 70 74 69 6f 6e 41 65 73 52 73 61 } //2 encryptionAesRsa
		$a_01_1 = {64 69 73 61 62 6c 65 52 65 63 6f 76 65 72 79 4d 6f 64 65 } //2 disableRecoveryMode
		$a_00_2 = {41 00 6c 00 6c 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //2 All of your files have been encrypted
		$a_00_3 = {72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 } //1 ransomware from your computer
		$a_80_4 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 2f 61 6c 6c 20 2f 2f 71 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //vssadmin delete shadows //all //quiet & wmic shadowcopy delete  1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1) >=7
 
}
rule Ransom_MSIL_Filecoder_NIT_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 4d 6f 72 67 61 6e 5c 4d 6f 72 67 61 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4d 6f 72 67 61 6e 2e 70 64 62 } //2 \source\repos\Morgan\Morgan\obj\Release\Morgan.pdb
		$a_00_1 = {2e 00 6d 00 6f 00 72 00 67 00 61 00 6e 00 } //2 .morgan
		$a_01_2 = {46 49 4c 45 5f 45 58 54 45 4e 53 49 4f 4e 53 } //2 FILE_EXTENSIONS
		$a_00_3 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 75 00 73 00 69 00 6e 00 67 00 20 00 41 00 45 00 53 00 } //2 Your files are encrypted using AES
		$a_00_4 = {53 00 50 00 49 00 46 00 5f 00 55 00 50 00 44 00 41 00 54 00 45 00 49 00 4e 00 49 00 46 00 49 00 4c 00 45 00 } //1 SPIF_UPDATEINIFILE
		$a_00_5 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 } //1 \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}