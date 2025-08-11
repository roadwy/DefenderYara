
rule Ransom_MSIL_TankRansom_SL_MTB{
	meta:
		description = "Ransom:MSIL/TankRansom.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {54 61 6e 6b 69 20 58 20 52 61 6e 73 6f 6d 77 61 72 65 20 34 2e 30 } //2 Tanki X Ransomware 4.0
		$a_81_1 = {41 74 74 65 6e 74 69 6f 6e 21 20 59 6f 75 72 20 4f 53 20 61 6e 64 20 79 6f 75 72 20 66 69 6c 65 73 20 69 73 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 54 61 6e 6b 69 20 58 20 52 61 6e 73 6f 6d 77 61 72 65 } //2 Attention! Your OS and your files is encrypted by Tanki X Ransomware
		$a_81_2 = {24 36 37 36 31 66 64 39 37 2d 32 63 39 62 2d 34 66 62 31 2d 61 63 36 63 2d 63 61 31 33 32 33 32 30 37 65 37 61 } //2 $6761fd97-2c9b-4fb1-ac6c-ca1323207e7a
		$a_81_3 = {41 72 68 69 62 6f 74 54 61 6e 6b 69 58 4c 61 72 6e 79 31 33 33 37 } //2 ArhibotTankiXLarny1337
		$a_81_4 = {2f 6b 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 41 76 61 73 74 55 49 2e 65 78 65 20 26 26 20 65 78 69 74 } //2 /k taskkill /f /im AvastUI.exe && exit
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}