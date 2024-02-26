
rule Trojan_BAT_LokiBot_RDK_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 } //01 00  server1
		$a_01_1 = {4a 69 6e 73 20 73 47 6c 6f 62 61 6c 20 49 6e 63 } //01 00  Jins sGlobal Inc
		$a_01_2 = {66 61 73 4d 6c 30 39 4e 79 34 49 55 31 5a 32 30 58 55 71 70 43 7a 77 6f 42 52 39 63 53 5a 41 74 4b 43 6c 43 63 59 39 33 66 79 32 66 53 4f 6c 62 44 78 32 75 7a 6c 46 33 78 45 73 43 42 63 66 49 32 73 54 31 35 55 4c } //00 00  fasMl09Ny4IU1Z20XUqpCzwoBR9cSZAtKClCcY93fy2fSOlbDx2uzlF3xEsCBcfI2sT15UL
	condition:
		any of ($a_*)
 
}