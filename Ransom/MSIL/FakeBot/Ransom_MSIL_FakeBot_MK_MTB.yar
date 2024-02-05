
rule Ransom_MSIL_FakeBot_MK_MTB{
	meta:
		description = "Ransom:MSIL/FakeBot.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //YOUR FILES ARE ENCRYPTED  01 00 
		$a_80_1 = {69 6d 70 6f 72 74 61 6e 74 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 63 6f 70 69 65 64 20 74 6f 20 6f 75 72 20 76 61 75 6c 74 } //important data has been copied to our vault  01 00 
		$a_80_2 = {53 45 4e 44 4d 59 69 44 62 6f 74 } //SENDMYiDbot  01 00 
		$a_80_3 = {63 6f 73 74 20 69 6e 63 72 65 61 73 65 73 20 77 69 74 68 20 74 69 6d 65 2c 20 64 6f 6e 27 74 20 77 61 73 74 65 20 79 6f 75 72 20 74 69 6d 65 } //cost increases with time, don't waste your time  00 00 
		$a_00_4 = {5d 04 00 } //00 9c 
	condition:
		any of ($a_*)
 
}