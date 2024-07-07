
rule Ransom_MSIL_Kraken_B{
	meta:
		description = "Ransom:MSIL/Kraken.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {4b 00 72 00 61 00 6b 00 65 00 6e 00 2e 00 65 00 78 00 65 00 } //1 Kraken.exe
		$a_01_1 = {22 61 6e 74 69 5f 72 65 76 65 72 65 22 3a 74 72 75 65 2c } //1 "anti_revere":true,
		$a_01_2 = {22 65 78 74 65 6e 73 69 6f 6e 5f 62 79 70 61 73 73 22 3a 74 72 75 65 2c } //1 "extension_bypass":true,
		$a_01_3 = {4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 45 44 20 55 4e 49 51 55 45 20 4b 45 59 } //1 KRAKEN ENCRYPTED UNIQUE KEY
		$a_03_4 = {4e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 79 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 90 02 06 4b 52 41 4b 45 4e 20 44 45 43 52 59 50 54 4f 52 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}