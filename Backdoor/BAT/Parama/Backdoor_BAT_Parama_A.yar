
rule Backdoor_BAT_Parama_A{
	meta:
		description = "Backdoor:BAT/Parama.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {4f 70 65 6e 69 6e 67 20 72 65 6d 6f 74 65 20 63 6d 64 2e 2e 2e } //Opening remote cmd...  01 00 
		$a_80_1 = {41 74 74 65 6d 70 69 6e 67 20 74 6f 20 63 6f 6e 6e 65 63 74 20 74 6f 3a 20 7b 30 7d 3a 7b 31 7d } //Attemping to connect to: {0}:{1}  01 00 
		$a_80_2 = {46 6c 6f 6f 64 69 6e 67 20 77 69 74 68 20 41 52 4d 45 2e 20 49 50 3a } //Flooding with ARME. IP:  01 00 
		$a_80_3 = {53 74 6f 70 70 65 64 20 46 6c 6f 6f 64 69 6e 67 2e 2e 2e } //Stopped Flooding...  01 00 
		$a_80_4 = {52 65 6d 6f 74 65 20 63 61 6d 20 73 74 61 72 74 65 64 2e 2e 2e } //Remote cam started...  00 00 
		$a_00_5 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}