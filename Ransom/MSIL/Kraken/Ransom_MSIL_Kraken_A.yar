
rule Ransom_MSIL_Kraken_A{
	meta:
		description = "Ransom:MSIL/Kraken.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 00 72 00 61 00 6b 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  Kraken.exe
		$a_01_1 = {22 61 6e 74 69 5f 66 6f 72 65 6e 73 69 63 22 3a 74 72 75 65 2c } //01 00  "anti_forensic":true,
		$a_01_2 = {22 61 6e 74 69 5f 72 65 76 65 72 65 22 3a 74 72 75 65 2c } //01 00  "anti_revere":true,
		$a_01_3 = {57 68 65 6e 20 74 68 65 20 72 65 73 65 61 72 63 68 65 72 73 20 70 61 72 74 79 20 68 61 72 64 2c 20 6f 75 72 20 70 61 72 74 69 65 73 20 68 61 72 64 65 72 } //00 00  When the researchers party hard, our parties harder
	condition:
		any of ($a_*)
 
}