
rule TrojanDropper_BAT_Zaptoya_A_bit{
	meta:
		description = "TrojanDropper:BAT/Zaptoya.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 45 61 63 68 20 69 20 49 6e 20 53 70 6c 69 74 28 48 65 78 2c 20 22 2a 2a 2a 2a 2a 2a 40 40 40 40 40 40 40 40 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2f 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 40 40 40 40 40 40 40 40 40 40 2b 2b 2b 2b 2b 2b 2b 2b 22 29 } //1 For Each i In Split(Hex, "******@@@@@@@@///////////***********@@@@@@@@@@++++++++")
		$a_02_1 = {43 3a 5c 55 73 65 72 73 5c 44 45 4c 4c 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 90 02 20 5c 90 02 20 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 68 72 6f 6d 65 53 65 74 75 70 2e 70 64 62 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}