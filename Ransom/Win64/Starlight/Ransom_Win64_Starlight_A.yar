
rule Ransom_Win64_Starlight_A{
	meta:
		description = "Ransom:Win64/Starlight.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {37 63 77 4d 71 6d 35 30 43 72 6b 63 33 6c 44 51 57 52 4c 45 35 4d 59 45 69 53 76 54 33 70 69 6c 38 64 42 42 52 37 58 58 4a 4b 6a 56 78 33 4e 4d 57 56 76 50 49 63 73 3d } //1 7cwMqm50Crkc3lDQWRLE5MYEiSvT3pil8dBBR7XXJKjVx3NMWVvPIcs=
		$a_01_1 = {66 43 6e 79 2f 70 4d 67 4e 41 4f 37 47 78 55 38 4a 59 63 61 72 64 50 2f 33 50 51 6f 56 53 7a 5a 30 7a 50 62 44 41 78 62 65 76 74 61 4a 41 69 43 35 6f 53 5a 56 4b 36 4f 56 62 66 30 64 62 72 43 41 71 6a 57 56 39 77 53 47 4f 32 } //1 fCny/pMgNAO7GxU8JYcardP/3PQoVSzZ0zPbDAxbevtaJAiC5oSZVK6OVbf0dbrCAqjWV9wSGO2
		$a_01_2 = {64 65 63 72 79 70 74 5f 6b 65 79 2e 6e 6b 79 } //1 decrypt_key.nky
		$a_01_3 = {72 61 6e 73 6f 6d 77 61 72 65 2e 72 73 } //1 ransomware.rs
		$a_01_4 = {45 6e 63 72 79 70 74 69 6e 67 20 6c 61 72 67 65 20 66 69 6c 65 } //1 Encrypting large file
		$a_01_5 = {41 6c 6c 20 74 68 65 20 66 69 6c 65 73 20 69 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All the files in your computer has been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}