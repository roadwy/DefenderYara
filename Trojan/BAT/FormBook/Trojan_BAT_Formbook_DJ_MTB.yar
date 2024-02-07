
rule Trojan_BAT_Formbook_DJ_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 37 32 39 61 63 63 35 63 2d 61 61 33 39 2d 34 33 61 32 2d 61 36 63 64 2d 64 34 39 30 66 35 61 61 39 66 34 36 } //01 00  $729acc5c-aa39-43a2-a6cd-d490f5aa9f46
		$a_81_1 = {67 65 74 5f 4d 61 6e 61 67 65 72 5f 70 61 73 73 77 6f 72 64 } //01 00  get_Manager_password
		$a_81_2 = {67 65 74 5f 47 6f 6f 64 73 5f 61 6d 6f 75 6e 74 } //01 00  get_Goods_amount
		$a_81_3 = {57 61 72 65 68 6f 75 73 65 } //01 00  Warehouse
		$a_81_4 = {50 61 73 73 77 6f 72 64 74 65 78 74 } //01 00  Passwordtext
		$a_81_5 = {31 32 33 34 35 36 } //00 00  123456
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Formbook_DJ_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 36 32 38 64 36 62 36 34 2d 31 36 33 65 2d 34 37 31 64 2d 38 32 32 37 2d 35 64 34 33 33 38 36 35 31 32 65 31 } //01 00  $628d6b64-163e-471d-8227-5d43386512e1
		$a_81_1 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 72 2e 6c 6f 67 } //01 00  screencapturer.log
		$a_81_2 = {4d 6f 75 73 65 4b 65 79 54 72 69 67 67 65 72 73 } //01 00  MouseKeyTriggers
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_4 = {53 63 72 65 65 6e 43 61 70 74 75 72 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  ScreenCapturer.Properties
		$a_81_5 = {4c 6f 67 67 65 72 } //00 00  Logger
	condition:
		any of ($a_*)
 
}