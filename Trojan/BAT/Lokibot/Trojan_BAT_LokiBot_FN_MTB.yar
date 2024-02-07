
rule Trojan_BAT_LokiBot_FN_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 1f a2 0b 09 0f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 a2 00 00 00 36 00 00 00 c3 00 00 00 4a } //0a 00 
		$a_01_1 = {57 df a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a9 00 00 00 40 00 00 00 ee 00 00 00 ae } //01 00 
		$a_01_2 = {24 34 39 66 65 32 34 38 35 2d 31 63 33 63 2d 34 32 66 65 2d 62 61 66 64 2d 39 35 61 61 30 38 31 34 63 33 31 66 } //01 00  $49fe2485-1c3c-42fe-bafd-95aa0814c31f
		$a_81_3 = {53 74 61 72 5f 57 61 72 73 5f 54 68 65 5f 45 6d 70 69 72 65 5f 53 74 72 69 6b 65 73 5f 42 61 63 6b 5f 69 63 6f 6e } //01 00  Star_Wars_The_Empire_Strikes_Back_icon
		$a_01_4 = {58 43 43 56 56 } //01 00  XCCVV
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {41 63 74 69 76 61 74 6f 72 } //00 00  Activator
	condition:
		any of ($a_*)
 
}