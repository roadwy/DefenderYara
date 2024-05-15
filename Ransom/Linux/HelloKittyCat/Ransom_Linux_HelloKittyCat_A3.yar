
rule Ransom_Linux_HelloKittyCat_A3{
	meta:
		description = "Ransom:Linux/HelloKittyCat.A3,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 74 61 72 74 5f 65 6e 63 } //start_enc  01 00 
		$a_80_1 = {65 6e 63 5f 64 6f 6e 65 } //enc_done  02 00 
		$a_80_2 = {49 54 53 53 48 4f 57 4b 45 59 } //ITSSHOWKEY  02 00 
		$a_80_3 = {70 72 65 70 61 72 65 20 49 54 53 42 54 43 20 62 74 63 } //prepare ITSBTC btc  02 00 
		$a_80_4 = {63 6f 6e 74 61 63 74 20 65 6d 61 69 6c 3a 49 54 53 45 4d 41 49 4c } //contact email:ITSEMAIL  02 00 
		$a_80_5 = {47 47 47 49 54 53 53 48 4f 57 4b 45 59 30 30 } //GGGITSSHOWKEY00  03 00 
		$a_80_6 = {73 65 72 76 69 63 65 40 68 65 6c 6c 6f 6b 69 74 74 79 63 61 74 2e 6f 6e 6c 69 6e 65 } //service@hellokittycat.online  00 00 
	condition:
		any of ($a_*)
 
}