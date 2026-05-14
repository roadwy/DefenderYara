
rule Ransom_MSIL_LockScreen_A_AMTB{
	meta:
		description = "Ransom:MSIL/LockScreen.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_81_0 = {59 4f 55 20 41 52 45 20 48 41 43 4b 45 44 21 } //1 YOU ARE HACKED!
		$a_81_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_81_2 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d 20 45 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 66 } //1 taskkill.exe /im Explorer.exe /f
		$a_81_3 = {43 72 79 70 74 6f 72 20 5b 52 75 6e 74 69 6d 65 5d } //1 Cryptor [Runtime]
		$a_02_4 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 [0-50] 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 2e 00 } //1
		$a_02_5 = {53 65 72 76 69 63 65 20 [0-50] 20 73 74 61 72 74 65 64 2e } //1
		$a_81_6 = {26 20 64 65 6c 20 69 6e 66 6f 2d 4c 6f 63 6b 65 72 2e 74 78 74 20 2f 71 20 2f 73 } //2 & del info-Locker.txt /q /s
		$a_81_7 = {4d 65 6d 6f 72 79 20 73 65 63 74 69 6f 6e 20 61 74 20 61 64 64 72 65 73 73 20 30 78 30 34 32 34 2a 20 69 73 20 6c 6f 63 6b 65 64 } //2 Memory section at address 0x0424* is locked
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2) >=7
 
}