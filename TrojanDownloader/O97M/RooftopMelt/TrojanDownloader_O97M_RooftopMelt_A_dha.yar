
rule TrojanDownloader_O97M_RooftopMelt_A_dha{
	meta:
		description = "TrojanDownloader:O97M/RooftopMelt.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 90 01 20 90 02 20 2f 73 65 6e 64 4d 65 73 73 61 67 65 90 00 } //1
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 6d 79 2d 69 70 2e 69 6f 2f 69 70 } //1 https://api.my-ip.io/ip
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 47 65 74 55 73 65 72 4e 61 6d 65 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 54 65 6d 70 6c 61 74 65 73 5c } //1 C:\Users\" & GetUserName & "\AppData\Roaming\Microsoft\Templates\
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}