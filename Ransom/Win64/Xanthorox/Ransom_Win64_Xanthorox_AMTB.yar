
rule Ransom_Win64_Xanthorox_AMTB{
	meta:
		description = "Ransom:Win64/Xanthorox!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 58 61 6e 74 68 6f 72 6f 78 20 41 49 20 62 61 73 65 64 20 52 61 6e 73 6f 6d 77 61 72 65 } //All your files have been encrypted by Xanthorox AI based Ransomware  1
		$a_80_1 = {2e 2e 2e 20 50 41 53 54 45 20 59 4f 55 52 20 46 55 4c 4c 20 52 41 4e 53 4f 4d 20 4e 4f 54 45 20 48 45 52 45 20 2e 2e 2e 20 7b 56 49 43 54 49 4d 5f 49 44 7d 20 2e 2e 2e } //... PASTE YOUR FULL RANSOM NOTE HERE ... {VICTIM_ID} ...  1
		$a_80_2 = {58 61 6e 74 68 6f 72 6f 78 49 6e 73 74 61 6e 63 65 4d 75 74 65 78 5f 76 33 5f 46 69 6e 61 6c 5f 55 6e 69 71 75 65 } //XanthoroxInstanceMutex_v3_Final_Unique  1
		$a_80_3 = {43 3a 5c 54 45 4d 50 5c 78 61 6e 74 68 6f 72 6f 78 5f 6c 6f 67 2e 74 78 74 } //C:\TEMP\xanthorox_log.txt  1
		$a_80_4 = {58 41 4e 54 48 4f 52 4f 58 20 56 33 20 48 49 54 } //XANTHOROX V3 HIT  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}