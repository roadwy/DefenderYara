
rule Trojan_BAT_Formbook_FC_MTB{
	meta:
		description = "Trojan:BAT/Formbook.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 64 34 30 38 63 32 36 35 2d 61 66 33 65 2d 34 33 38 66 2d 62 36 61 66 2d 39 62 64 63 35 38 36 36 35 64 65 36 } //20 $d408c265-af3e-438f-b6af-9bdc58665de6
		$a_81_1 = {43 6f 6c 6f 72 50 61 6c 65 74 74 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //20 ColorPalette.Properties.Resources
		$a_81_2 = {43 72 6f 70 65 64 49 6d 61 67 65 } //1 CropedImage
		$a_81_3 = {69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //1 information.txt
		$a_81_4 = {6f 75 74 6c 6f 6f 6b 2e 74 78 74 } //1 outlook.txt
		$a_81_5 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 passwords.txt
		$a_81_6 = {57 61 6c 6c 65 74 73 2f 45 78 6f 64 75 73 } //1 Wallets/Exodus
		$a_81_7 = {63 6f 6f 6b 69 65 5f 6c 69 73 74 2e 74 78 74 } //1 cookie_list.txt
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=26
 
}