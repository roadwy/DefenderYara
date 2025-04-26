
rule Ransom_Win64_Snatch_PA_MTB{
	meta:
		description = "Ransom:Win64/Snatch.PA!MTB,SIGNATURE_TYPE_PEHSTR,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 32 73 4b 36 67 53 57 37 33 34 4e 66 42 67 75 75 79 6e 30 48 2f 46 54 46 55 6c 6f 4c 6f 69 41 72 6f 56 47 54 36 4a 62 5f 45 2f 46 32 6a 6e 46 39 56 5a 43 39 4a 70 42 4e 54 4a 5f 6f 76 4f 2f 38 74 5f 38 76 31 6f 7a 64 33 4b 36 39 52 58 5f 53 78 76 4f } //10 Go build ID: "2sK6gSW734NfBguuyn0H/FTFUloLoiAroVGT6Jb_E/F2jnF9VZC9JpBNTJ_ovO/8t_8v1ozd3K69RX_SxvO
		$a_01_1 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //10 at  fp= is  lr: of  on  pc= sp: sp=
		$a_01_2 = {43 46 4c 4d 4e 50 53 5a } //1 CFLMNPSZ
		$a_01_3 = {65 6e 63 72 79 70 74 } //1 encrypt
		$a_01_4 = {64 65 63 72 79 70 74 } //1 decrypt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}