
rule Ransom_MSIL_Covid_SK_MTB{
	meta:
		description = "Ransom:MSIL/Covid.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {79 6f 75 20 62 65 63 61 6d 65 20 61 20 76 69 63 74 69 6d 20 6f 66 20 63 6f 76 69 64 2d 33 32 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 you became a victim of covid-32 ransomware
		$a_81_1 = {35 20 6d 69 6e 73 20 74 6f 20 70 61 79 20 6f 72 20 65 6c 73 65 20 79 6f 75 20 77 69 6c 6c 20 6c 6f 73 65 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 61 6c 73 6f 20 79 6f 75 72 20 4d 42 52 } //1 5 mins to pay or else you will lose all your data and also your MBR
		$a_81_2 = {62 6c 61 63 6b 5f 77 61 6c 6c 70 61 70 65 72 2e 62 6d 70 } //1 black_wallpaper.bmp
		$a_81_3 = {52 45 41 44 4d 45 57 48 41 54 59 4f 55 44 49 44 2e 74 78 74 } //1 READMEWHATYOUDID.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}