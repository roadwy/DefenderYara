
rule Trojan_BAT_SnakeKeylogger_SPAF_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 72 6d 5f 48 73 76 43 6f 6c 6f 72 70 69 63 6b 65 72 5f 4c 6f 61 64 } //01 00  frm_HsvColorpicker_Load
		$a_01_1 = {4e 69 63 6f 50 69 7a 7a 65 72 69 61 2e 45 78 74 65 6e 73 69 6f 6e 73 } //01 00  NicoPizzeria.Extensions
		$a_01_2 = {4e 69 63 6f 50 69 7a 7a 65 72 69 61 2e 48 65 6c 70 65 72 73 } //01 00  NicoPizzeria.Helpers
		$a_01_3 = {66 72 6d 5f 48 73 76 43 6f 6c 6f 72 70 69 63 6b 65 72 } //01 00  frm_HsvColorpicker
		$a_01_4 = {67 65 74 5f 4d 61 72 6c 69 65 63 65 5f 34 35 5f 41 6e 64 72 61 64 61 } //01 00  get_Marliece_45_Andrada
		$a_01_5 = {67 65 74 5f 4d 61 72 6c 69 65 63 65 5f 41 6e 64 72 61 64 61 } //01 00  get_Marliece_Andrada
		$a_01_6 = {4e 69 63 6f 50 69 7a 7a 65 72 69 61 } //00 00  NicoPizzeria
	condition:
		any of ($a_*)
 
}