
rule Trojan_BAT_Stelega_DG_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 38 31 38 64 39 32 66 38 2d 63 61 38 33 2d 34 39 39 32 2d 39 39 63 37 2d 65 66 63 37 38 65 36 35 66 39 30 39 } //20 $818d92f8-ca83-4992-99c7-efc78e65f909
		$a_81_1 = {50 69 78 65 6c 53 6f 72 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 PixelSorter.Properties.Resources
		$a_81_2 = {63 6f 6f 6b 69 65 5f 6c 69 73 74 2e 74 78 74 } //1 cookie_list.txt
		$a_81_3 = {6f 75 74 6c 6f 6f 6b 2e 74 78 74 } //1 outlook.txt
		$a_81_4 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_81_5 = {68 69 73 74 6f 72 79 5f 4d 6f 7a 69 6c 6c 61 20 46 69 72 65 66 6f 78 } //1 history_Mozilla Firefox
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=25
 
}