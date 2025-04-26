
rule Ransom_Win64_EByte_AUJ_MTB{
	meta:
		description = "Ransom:Win64/EByte.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 69 6f 6e 20 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e 74 78 74 } //1 Decryption Instructions.txt
		$a_01_1 = {6c 6f 63 6b 65 72 2d 31 37 33 37 39 31 36 33 34 34 37 34 39 32 39 31 32 30 30 } //1 locker-1737916344749291200
		$a_01_2 = {45 42 79 74 65 2d 52 77 61 72 65 2f 65 6e 63 72 79 70 74 69 6f 6e 2e 45 6e 63 72 79 70 74 46 69 6c 65 } //1 EByte-Rware/encryption.EncryptFile
		$a_01_3 = {6d 61 69 6e 2e 73 65 74 57 61 6c 6c 70 61 70 65 72 } //1 main.setWallpaper
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}