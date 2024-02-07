
rule TrojanProxy_BAT_Banker_A{
	meta:
		description = "TrojanProxy:BAT/Banker.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 78 00 74 00 6d 00 6f 00 64 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 2e 00 74 00 78 00 74 00 } //01 00  txtmodificado.txt
		$a_01_1 = {68 00 6f 00 73 00 74 00 2c 00 20 00 62 00 61 00 6e 00 72 00 69 00 } //01 00  host, banri
		$a_01_2 = {68 00 6f 00 73 00 74 00 2c 00 20 00 63 00 69 00 74 00 69 00 } //01 00  host, citi
		$a_01_3 = {63 00 68 00 65 00 63 00 6b 00 69 00 6e 00 66 00 65 00 63 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  checkinfect.txt
		$a_01_4 = {50 00 52 00 4f 00 58 00 59 00 20 00 78 00 73 00 65 00 6e 00 68 00 61 00 } //00 00  PROXY xsenha
	condition:
		any of ($a_*)
 
}