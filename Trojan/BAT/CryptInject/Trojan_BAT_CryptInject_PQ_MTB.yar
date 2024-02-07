
rule Trojan_BAT_CryptInject_PQ_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 39 33 36 37 65 32 35 66 2d 37 61 62 65 2d 34 64 63 38 2d 38 62 30 31 2d 39 35 34 66 36 34 37 33 32 35 31 64 } //01 00  $9367e25f-7abe-4dc8-8b01-954f6473251d
		$a_81_1 = {57 6f 72 4d 53 } //01 00  WorMS
		$a_81_2 = {57 6f 72 4d 53 2e 66 72 6d 53 75 70 4d 61 6e 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WorMS.frmSupMan.resources
		$a_81_3 = {57 6f 72 4d 53 2e 52 65 73 6f 75 72 63 65 73 5f 69 63 6f 6e 2e 70 6e 67 } //01 00  WorMS.Resources_icon.png
		$a_81_4 = {52 65 73 6f 75 72 63 65 5f 53 74 6f 63 6b 2e 64 61 74 } //01 00  Resource_Stock.dat
		$a_81_5 = {52 65 73 6f 75 72 63 65 5f 53 74 6f 63 6b 5f 74 65 6d 70 2e 64 61 74 } //01 00  Resource_Stock_temp.dat
		$a_81_6 = {62 75 74 43 68 61 6e 67 65 46 69 6c 65 44 69 72 2e 49 6d 61 67 65 } //01 00  butChangeFileDir.Image
		$a_81_7 = {52 65 6d 6f 74 65 20 44 65 73 6b 74 6f 70 20 43 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Remote Desktop Connection
		$a_81_8 = {57 6f 72 4d 53 2e 64 6c 67 48 6f 6d 65 53 63 72 65 65 6e 5f 43 68 61 6e 67 65 46 69 6c 65 44 69 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  WorMS.dlgHomeScreen_ChangeFileDir.resources
		$a_81_9 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 6d 6f 76 65 20 74 68 65 20 73 65 6c 65 63 74 65 64 20 72 65 73 6f 75 72 63 65 3f } //00 00  Are you sure you want to remove the selected resource?
	condition:
		any of ($a_*)
 
}