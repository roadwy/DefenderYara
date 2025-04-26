
rule TrojanDownloader_PowerShell_Elshutilo_AJ_MTB{
	meta:
		description = "TrojanDownloader:PowerShell/Elshutilo.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 66 31 2c 20 22 2f 5c 22 2c 20 22 32 22 29 29 } //1 Replace(f1, "/\", "2"))
		$a_01_1 = {52 65 70 6c 61 63 65 28 22 50 6f 77 23 26 2a 24 25 65 6c 6c 22 2c 20 22 23 26 2a 24 25 22 2c 20 22 65 72 73 68 22 29 29 } //1 Replace("Pow#&*$%ell", "#&*$%", "ersh"))
		$a_03_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f 20 28 [0-0b] 20 2b 20 22 22 22 22 20 2b 20 ?? 20 2b 20 22 22 22 22 20 2b 20 22 2c 20 22 20 2b 20 22 22 22 22 20 2b 20 ?? 20 2b 20 22 22 22 22 20 2b 20 22 2c 20 22 22 22 22 2c 20 30 29 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}