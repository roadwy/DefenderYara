
rule TrojanSpy_BAT_Keylog_A{
	meta:
		description = "TrojanSpy:BAT/Keylog.A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4b 00 69 00 6e 00 67 00 20 00 4b 00 6f 00 6e 00 67 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //05 00  King Kong Keylogger
		$a_01_1 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 4c 00 6f 00 67 00 } //05 00  Keylogger Log
		$a_01_2 = {00 73 68 69 66 74 61 6e 64 63 61 70 73 00 } //0f 00  猀楨瑦湡捤灡s
		$a_01_3 = {00 4b 65 79 62 6f 61 72 64 50 72 6f 63 00 } //00 00  䬀祥潢牡偤潲c
	condition:
		any of ($a_*)
 
}