
rule Trojan_Win32_Guloader_SX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {62 6c 61 64 6b 72 69 67 65 6e 2e 65 78 65 } //1 bladkrigen.exe
		$a_81_1 = {46 72 61 64 72 61 67 65 5c 72 61 62 61 72 62 65 72 67 72 64 5c 6a 65 6e 67 65 6e 65 } //1 Fradrage\rabarbergrd\jengene
		$a_81_2 = {6d 75 67 67 65 64 5c 61 75 67 6d 65 6e 74 65 72 73 } //1 mugged\augmenters
		$a_81_3 = {25 75 72 65 74 68 72 6f 67 65 6e 69 74 61 6c 25 5c 6d 65 64 6c 65 6d 5c 68 61 61 6e 64 74 61 67 65 74 73 2e 76 65 6c } //1 %urethrogenital%\medlem\haandtagets.vel
		$a_81_4 = {61 66 66 6c 61 64 6e 69 6e 67 65 6e 73 5c 61 75 74 6f 6d 65 6b 61 6e 69 6b 65 72 65 73 5c 66 6f 72 61 67 74 65 6c 69 67 65 73 } //1 affladningens\automekanikeres\foragteliges
		$a_81_5 = {62 75 73 79 62 6f 64 79 6e 65 73 73 2e 68 6a 65 } //1 busybodyness.hje
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}