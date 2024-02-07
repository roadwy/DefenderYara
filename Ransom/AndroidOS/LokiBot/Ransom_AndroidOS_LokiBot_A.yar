
rule Ransom_AndroidOS_LokiBot_A{
	meta:
		description = "Ransom:AndroidOS/LokiBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 43 72 69 70 74 41 63 74 69 76 69 74 79 3b } //01 00  /CriptActivity;
		$a_00_1 = {2f 53 63 72 79 6e 6c 6f 63 6b 3b } //01 00  /Scrynlock;
		$a_00_2 = {2f 46 6f 72 76 61 72 64 43 61 6c 6c 3b } //01 00  /ForvardCall;
		$a_00_3 = {2f 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 3b } //01 00  /InjectProcess;
		$a_00_4 = {2f 43 6f 6d 6d 61 6e 64 53 65 72 76 69 63 65 3b } //01 00  /CommandService;
		$a_00_5 = {2f 43 43 4c 6f 6b 65 72 3b } //00 00  /CCLoker;
		$a_00_6 = {5d 04 00 } //00 a7 
	condition:
		any of ($a_*)
 
}