
rule Trojan_BAT_LokiBot_SK_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 38 34 65 63 61 66 66 62 2d 33 65 62 34 2d 34 39 37 34 2d 61 62 39 35 2d 66 32 31 64 63 34 62 30 64 34 62 62 } //2 $84ecaffb-3eb4-4974-ab95-f21dc4b0d4bb
		$a_81_1 = {4e 4a 6e 4e 6f 69 38 38 37 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 NJnNoi887.Properties.Resources
		$a_81_2 = {4e 4a 6e 4e 6f 69 38 38 37 2e 65 78 65 } //2 NJnNoi887.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}