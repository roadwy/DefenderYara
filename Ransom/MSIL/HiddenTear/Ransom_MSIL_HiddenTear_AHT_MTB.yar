
rule Ransom_MSIL_HiddenTear_AHT_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.AHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 00 6f 00 72 00 6d 00 2e 00 6c 00 6f 00 67 00 } //4 worm.log
		$a_01_1 = {55 00 70 00 64 00 61 00 74 00 65 00 2e 00 6c 00 6e 00 6b 00 } //1 Update.lnk
		$a_01_2 = {5b 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00 5d 00 } //1 [InternetShortcut]
		$a_01_3 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 keylog.txt
		$a_01_4 = {5b 00 42 00 41 00 43 00 4b 00 53 00 50 00 41 00 43 00 45 00 5d 00 } //1 [BACKSPACE]
		$a_01_5 = {5b 00 54 00 41 00 42 00 5d 00 } //1 [TAB]
		$a_01_6 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //2 Your files have been encrypted
		$a_01_7 = {43 00 68 00 65 00 63 00 6b 00 20 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 20 00 6f 00 6e 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //3 Check READ_ME.txt on your desktop
		$a_01_8 = {54 00 52 00 55 00 45 00 57 00 30 00 52 00 4d 00 } //5 TRUEW0RM
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*3+(#a_01_8  & 1)*5) >=19
 
}
rule Ransom_MSIL_HiddenTear_AHT_MTB_2{
	meta:
		description = "Ransom:MSIL/HiddenTear.AHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 08 00 11 08 13 09 16 13 0a ?? ?? ?? ?? ?? 11 09 11 0a 9a 13 0b 00 11 0b 6f ?? 00 00 0a 2c 0f 11 0b 6f ?? 00 00 0a 19 fe 01 16 fe 01 2b 01 17 13 0e 11 0e 2c 05 } //2
		$a_01_1 = {54 68 65 20 53 65 63 75 72 69 74 79 20 6f 66 20 54 68 69 73 20 43 6f 6d 70 75 74 65 72 20 48 61 73 20 42 65 65 6e 20 43 6f 6d 70 72 6f 6d 69 73 65 64 } //1 The Security of This Computer Has Been Compromised
		$a_01_2 = {4a 75 70 69 74 65 72 4c 6f 63 6b 65 72 20 68 61 73 20 65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 74 68 65 20 64 61 74 61 20 6f 6e 20 74 68 69 73 20 63 6f 6d 70 75 74 65 72 20 77 69 74 68 20 6d 69 6c 69 74 61 72 79 2d 67 72 61 64 65 20 41 45 53 2d 32 35 36 20 65 6e 63 72 79 70 74 69 6f 6e } //3 JupiterLocker has encrypted all the data on this computer with military-grade AES-256 encryption
		$a_01_3 = {57 65 20 74 61 6b 65 20 6f 75 72 20 77 6f 72 6b 20 73 65 72 69 6f 75 73 6c 79 20 61 6e 64 20 75 6e 64 65 72 73 74 61 6e 64 20 74 68 61 74 20 79 6f 75 72 20 64 61 74 61 20 6d 61 79 20 62 65 20 73 65 6e 73 69 74 69 76 65 20 6f 72 20 69 6d 70 6f 72 74 61 6e 74 } //1 We take our work seriously and understand that your data may be sensitive or important
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=7
 
}