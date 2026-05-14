
rule Ransom_Win64_ClearWater_MKV_MTB{
	meta:
		description = "Ransom:Win64/ClearWater.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 4c 45 41 52 57 41 54 45 52 5f 52 45 41 44 4d 45 2e 74 78 74 } //2 CLEARWATER_README.txt
		$a_01_1 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 } //2 Your network has been breached and all data was encrypted
		$a_01_2 = {41 54 54 45 4e 54 49 4f 4e 21 } //1 ATTENTION!
		$a_01_3 = {44 6f 20 6e 6f 74 20 6d 6f 64 69 66 79 2c 20 72 65 6e 61 6d 65 20 6f 72 20 64 65 6c 65 74 65 20 66 69 6c 65 73 } //1 Do not modify, rename or delete files
		$a_01_4 = {54 6f 20 72 65 73 74 6f 72 65 20 61 6c 6c 20 79 6f 75 72 20 50 43 73 20 61 6e 64 20 67 65 74 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 77 6f 72 6b 69 6e 67 20 61 67 61 69 6e } //1 To restore all your PCs and get your network working again
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}