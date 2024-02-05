
rule Adware_BAT_Wareda_RS_MTB{
	meta:
		description = "Adware:BAT/Wareda.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 05 00 "
		
	strings :
		$a_80_0 = {35 34 2e 31 36 34 2e 31 34 34 2e 32 35 32 3a 31 30 30 30 30 } //54.164.144.252:10000  01 00 
		$a_80_1 = {67 65 74 4f 66 66 65 72 73 2e 70 68 70 } //getOffers.php  01 00 
		$a_80_2 = {72 75 6e 5f 6f 66 66 65 72 } //run_offer  01 00 
		$a_80_3 = {4c 69 73 74 4f 66 66 65 72 73 2e 70 68 70 } //ListOffers.php  01 00 
		$a_80_4 = {4d 6f 64 65 6c 4e 61 6d 65 } //ModelName  01 00 
		$a_80_5 = {50 43 4d 6f 64 65 6c } //PCModel  01 00 
		$a_80_6 = {61 70 70 43 61 6c 63 75 6c 61 74 6f 72 } //appCalculator  01 00 
		$a_80_7 = {61 70 70 43 61 6c 65 6e 64 61 72 } //appCalendar  01 00 
		$a_80_8 = {61 70 70 43 68 65 73 73 } //appChess  00 00 
	condition:
		any of ($a_*)
 
}