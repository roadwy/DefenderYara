
rule Ransom_MSIL_HakunaMatata_PDZ_MTB{
	meta:
		description = "Ransom:MSIL/HakunaMatata.PDZ!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {4b 49 4c 4c 5f 41 50 50 53 5f 45 4e 43 52 59 50 54 5f 41 47 41 49 4e } //3 KILL_APPS_ENCRYPT_AGAIN
		$a_01_1 = {46 55 4c 4c 5f 45 4e 43 52 59 50 54 } //3 FULL_ENCRYPT
		$a_01_2 = {64 61 74 61 54 6f 45 6e 63 72 79 70 74 } //2 dataToEncrypt
		$a_01_3 = {54 52 49 50 4c 45 5f 45 4e 43 52 59 50 54 } //2 TRIPLE_ENCRYPT
		$a_01_4 = {41 4c 4c 5f 44 52 49 56 45 53 } //1 ALL_DRIVES
		$a_01_5 = {54 41 52 47 45 54 45 44 5f 45 58 54 45 4e 53 49 4f 4e 53 } //1 TARGETED_EXTENSIONS
		$a_01_6 = {43 48 41 4e 47 45 5f 50 52 4f 43 45 53 53 5f 4e 41 4d 45 } //1 CHANGE_PROCESS_NAME
		$a_01_7 = {3c 52 45 43 55 52 53 49 56 45 5f 44 49 52 45 43 54 4f 52 59 5f 4c 4f 4f 4b 3e } //1 <RECURSIVE_DIRECTORY_LOOK>
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=14
 
}