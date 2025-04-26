
rule TrojanDownloader_BAT_Bisowig_B{
	meta:
		description = "TrojanDownloader:BAT/Bisowig.B,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 72 61 67 6f 6e 4d 79 74 68 } //5 DragonMyth
		$a_01_1 = {50 68 61 72 6d 69 6e 67 20 76 } //5 Pharming v
		$a_01_2 = {63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 66 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00 } //1 checkinfect.php
		$a_01_3 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 46 00 69 00 6e 00 64 00 50 00 72 00 6f 00 78 00 79 00 46 00 6f 00 72 00 55 00 52 00 4c 00 28 00 75 00 72 00 6c 00 2c 00 20 00 68 00 6f 00 73 00 74 00 29 00 } //1 function FindProxyForURL(url, host)
		$a_01_4 = {2f 00 2f 00 42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 } //1 //Banco do Brasil
		$a_01_5 = {50 00 52 00 4f 00 58 00 59 00 20 00 79 00 2e 00 66 00 75 00 74 00 75 00 72 00 65 00 68 00 6f 00 70 00 65 00 73 00 64 00 69 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 PROXY y.futurehopesdie.com
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}