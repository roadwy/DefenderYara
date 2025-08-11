
rule Ransom_MSIL_TankRansom_SK_MTB{
	meta:
		description = "Ransom:MSIL/TankRansom.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2e 54 41 4e 4b 49 58 } //1 .TANKIX
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 73 70 65 63 69 61 6c 20 61 6c 67 6f 72 69 74 68 6d 20 62 79 20 54 61 6e 6b 69 20 58 2e 20 59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 6d 75 73 69 63 2c 20 65 74 63 } //1 All your computer files has been encrypted with a special algorithm by Tanki X. Your documents, photos, music, etc
		$a_81_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 42 53 4f 44 2e 65 78 65 } //1 C:\Windows\BSOD.exe
		$a_81_3 = {54 61 6e 6b 52 61 6e 73 6f 6d 5f 33 2e 5f 30 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 TankRansom_3._0.Properties.Resources
		$a_81_4 = {43 3a 2f 57 69 6e 64 6f 77 73 2f 57 61 72 6e 69 6e 67 2e 6a 70 67 } //1 C:/Windows/Warning.jpg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}