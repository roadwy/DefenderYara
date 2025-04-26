
rule Trojan_BAT_LokiBot_SML_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {44 43 35 34 43 59 34 57 50 43 52 59 47 41 46 43 38 35 47 5a 49 46 } //1 DC54CY4WPCRYGAFC85GZIF
		$a_81_1 = {24 63 38 61 36 61 38 35 66 2d 31 32 66 39 2d 34 33 31 64 2d 61 31 32 36 2d 63 39 34 61 64 63 62 39 64 32 39 36 } //1 $c8a6a85f-12f9-431d-a126-c94adcb9d296
		$a_81_2 = {47 65 74 58 6f 72 42 79 74 65 } //1 GetXorByte
		$a_81_3 = {4a 61 70 61 6e 65 73 65 54 72 61 69 6e 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //1 JapaneseTrainer.Properties
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_LokiBot_SML_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.SML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {35 38 4f 38 35 35 37 35 34 38 47 35 35 32 50 35 37 48 46 35 52 38 } //1 58O8557548G552P57HF5R8
		$a_81_1 = {47 65 74 58 6f 72 42 79 74 65 } //1 GetXorByte
		$a_81_2 = {43 61 6c 63 75 6c 61 74 65 4b 69 } //1 CalculateKi
		$a_00_3 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a 28 55 00 00 06 13 0b 02 11 0b 28 56 00 00 06 13 0c 02 11 0c 28 57 00 00 06 13 0d 02 11 0d 28 58 00 00 06 13 0e 07 11 05 11 0e d2 9c 11 05 17 58 13 05 11 05 08 32 88 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule Trojan_BAT_LokiBot_SML_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.SML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a 28 55 00 00 06 13 0b 02 11 0b 28 56 00 00 06 13 0c 02 11 0c 28 57 00 00 06 13 0d 02 11 0d 28 58 00 00 06 13 0e 07 11 05 11 0e d2 9c 11 05 17 58 13 05 11 05 08 32 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}