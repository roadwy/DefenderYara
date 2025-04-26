
rule Ransom_Win64_MedusaLocker_MLM_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.MLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8d 55 c7 48 8d 4d 87 e8 a6 51 ff ff 33 d2 48 89 55 07 0f b6 44 15 ?? 30 03 48 ff c3 48 8b 55 07 48 ff c2 48 89 55 07 48 83 ef 01 75 } //5
		$a_01_1 = {5b 00 2b 00 5d 00 5b 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 5d 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 [+][Encrypt] Encrypted:
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 taskkill /f /im explorer.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}