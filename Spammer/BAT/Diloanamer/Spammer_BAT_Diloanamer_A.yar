
rule Spammer_BAT_Diloanamer_A{
	meta:
		description = "Spammer:BAT/Diloanamer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 53 4e 5f 53 70 61 6d 6d 65 72 2e 4d 79 } //1 MSN_Spammer.My
		$a_01_1 = {4d 00 61 00 64 00 65 00 20 00 62 00 79 00 20 00 50 00 61 00 6e 00 69 00 6e 00 6f 00 44 00 61 00 6e 00 69 00 6c 00 6f 00 } //1 Made by PaninoDanilo
		$a_01_2 = {70 00 61 00 6e 00 69 00 6e 00 6f 00 64 00 61 00 6e 00 69 00 6c 00 6f 00 2e 00 61 00 6c 00 74 00 65 00 72 00 76 00 69 00 73 00 74 00 61 00 2e 00 6f 00 72 00 67 00 } //1 paninodanilo.altervista.org
		$a_01_3 = {4d 00 53 00 4e 00 5f 00 53 00 70 00 61 00 6d 00 6d 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 MSN_Spammer.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}