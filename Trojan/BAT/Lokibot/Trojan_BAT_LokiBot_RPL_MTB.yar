
rule Trojan_BAT_LokiBot_RPL_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1b 59 1c 58 0d 09 17 32 ce 06 17 58 0a 08 1a 59 1b 58 0c 08 20 00 d8 00 00 32 b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LokiBot_RPL_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 00 59 00 48 00 47 00 44 00 52 00 57 00 55 00 49 00 59 00 47 00 46 00 49 00 46 00 57 00 48 00 49 00 55 00 57 00 46 00 48 00 46 00 57 00 4a 00 4b 00 49 00 } //1 UYHGDRWUIYGFIFWHIUWFHFWJKI
		$a_01_1 = {34 00 46 00 46 00 4a 00 35 00 38 00 37 00 47 00 38 00 35 00 37 00 47 00 43 00 35 00 44 00 47 00 59 00 34 00 34 00 38 00 34 00 38 00 } //1 4FFJ587G857GC5DGY44848
		$a_01_2 = {47 00 65 00 74 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 GetObject
		$a_01_3 = {43 00 6f 00 6e 00 73 00 6f 00 6c 00 61 00 73 00 } //1 Consolas
		$a_01_4 = {41 73 79 6e 63 43 } //1 AsyncC
		$a_01_5 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}