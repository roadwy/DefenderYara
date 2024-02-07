
rule Trojan_BAT_AgentTesla_MAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {1d 2c 03 17 2b 03 16 2b 00 2d 1c 2b 14 06 74 04 00 00 1b 18 2c 03 17 2b 03 16 2b 00 2d 0c 26 2b 03 26 2b e9 07 2b 06 0a 2b e3 0b 2b f7 } //05 00 
		$a_01_1 = {42 70 67 76 75 6b 70 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00  Bpgvukp.Properties
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //02 00  CreateDecryptor
		$a_01_3 = {6c 00 6c 00 64 00 2e 00 6a 00 6e 00 79 00 73 00 63 00 62 00 67 00 64 00 72 00 73 00 78 00 6e 00 63 00 63 00 6b 00 62 00 70 00 6a 00 7a 00 71 00 64 00 78 00 4b 00 } //02 00  lld.jnyscbgdrsxncckbpjzqdxK
		$a_01_4 = {6e 00 6f 00 69 00 74 00 61 00 6c 00 73 00 6e 00 61 00 72 00 54 00 } //00 00  noitalsnarT
	condition:
		any of ($a_*)
 
}