
rule Trojan_BAT_Redwer_DD_MTB{
	meta:
		description = "Trojan:BAT/Redwer.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {48 65 72 65 47 6f 65 73 54 68 65 46 69 6c 65 54 6f 44 72 6f 70 } //HereGoesTheFileToDrop  3
		$a_80_1 = {73 65 63 72 65 74 6b 65 79 39 38 33 34 37 35 36 38 32 33 34 37 36 79 30 32 38 33 37 34 36 } //secretkey9834756823476y0283746  3
		$a_80_2 = {61 63 74 69 76 65 74 69 6d 65 2e 74 78 74 } //activetime.txt  3
		$a_80_3 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //GetFolderPath  3
		$a_80_4 = {5c 57 69 6e 44 65 66 65 6e 64 65 72 5c 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 } //\WinDefender\WindowsDefender  3
		$a_80_5 = {45 78 74 72 61 63 74 52 65 73 6f 75 72 63 65 } //ExtractResource  3
		$a_80_6 = {49 6e 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 43 6f 6e 73 6f 6c 65 } //IntelManagementConsole  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}