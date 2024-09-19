
rule TrojanDownloader_O97M_StrelaStealer_SIO_MTB{
	meta:
		description = "TrojanDownloader:O97M/StrelaStealer.SIO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 67 69 74 6c 61 62 2e 63 6f 6d 2f 44 65 6d 6f 54 72 6f 6a 61 6e 2f 72 65 61 6c 2f 2d 2f 72 61 77 2f 6d 61 69 6e 2f 63 68 65 63 6b 2e 62 61 74 } //1 https://gitlab.com/DemoTrojan/real/-/raw/main/check.bat
		$a_03_1 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 2d 4c 20 2d 6f 20 25 41 50 50 44 41 54 41 25 5c 50 75 6e 2e 62 61 74 20 22 20 26 20 [0-2f] 20 26 20 22 20 26 26 20 25 41 50 50 44 41 54 41 25 5c 50 75 6e 2e 62 61 74 22 29 2c 20 76 62 48 69 64 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}