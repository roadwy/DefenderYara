
rule Ransom_Win32_Nokonoko_PAA_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 6f 75 6c 64 6e 27 74 20 63 72 65 61 74 65 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 } //1 Couldn't create ransom note
		$a_01_1 = {43 6f 75 6c 64 6e 27 74 20 72 65 6e 61 6d 65 20 66 69 6c 65 } //1 Couldn't rename file
		$a_01_2 = {44 45 4c 45 54 45 5f 53 48 41 44 4f 57 5c } //1 DELETE_SHADOW\
		$a_01_3 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 } //1 delete shadow copies
		$a_01_4 = {51 3a 5c 57 3a 5c 45 3a 5c 52 3a 5c 54 3a 5c 59 3a 5c 55 3a 5c 49 3a 5c 4f 3a 5c 50 3a 5c 41 3a 5c 53 3a 5c 44 3a 5c 46 3a 5c 47 3a 5c 48 3a 5c 4a 3a 5c 4b 3a 5c 4c 3a 5c 5a 3a 5c 58 3a 5c 43 3a 5c 56 3a 5c 42 3a 5c 4e 3a 5c 4d 3a 5c } //1 Q:\W:\E:\R:\T:\Y:\U:\I:\O:\P:\A:\S:\D:\F:\G:\H:\J:\K:\L:\Z:\X:\C:\V:\B:\N:\M:\
		$a_01_5 = {2f 72 75 73 74 63 2f } //1 /rustc/
		$a_01_6 = {45 4e 43 52 59 50 54 5f 4e 45 54 57 4f 52 4b } //1 ENCRYPT_NETWORK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}