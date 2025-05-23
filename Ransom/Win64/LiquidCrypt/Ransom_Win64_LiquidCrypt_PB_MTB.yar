
rule Ransom_Win64_LiquidCrypt_PB_MTB{
	meta:
		description = "Ransom:Win64/LiquidCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 74 00 78 00 74 00 } //1 \running.txt
		$a_01_1 = {4c 00 69 00 71 00 75 00 69 00 64 00 2e 00 68 00 74 00 61 00 } //1 Liquid.hta
		$a_01_2 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 20 00 69 00 73 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00 79 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 69 00 6e 00 } //1 encryptor is already running in
		$a_01_3 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 63 00 2e 00 65 00 78 00 65 00 } //1 \windows\system32\sc.exe
		$a_01_4 = {6e 00 6f 00 74 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 61 00 64 00 6d 00 69 00 6e 00 20 00 6e 00 65 00 74 00 77 00 72 00 6f 00 6b 00 73 00 20 00 69 00 73 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 } //1 not encrypting admin netwroks is enabled
		$a_03_5 = {5c 63 70 70 45 6e 64 5c [0-10] 5c 63 70 70 45 6e 64 78 36 34 2e 70 64 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}