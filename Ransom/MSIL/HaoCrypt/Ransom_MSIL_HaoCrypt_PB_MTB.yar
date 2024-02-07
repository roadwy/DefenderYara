
rule Ransom_MSIL_HaoCrypt_PB_MTB{
	meta:
		description = "Ransom:MSIL/HaoCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 2e 00 6d 00 65 00 2f 00 64 00 65 00 63 00 6f 00 76 00 69 00 64 00 31 00 39 00 62 00 6f 00 74 00 } //01 00  t.me/decovid19bot
		$a_01_1 = {2f 00 43 00 20 00 77 00 6d 00 69 00 63 00 20 00 63 00 73 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 67 00 65 00 74 00 20 00 55 00 55 00 49 00 44 00 } //01 00  /C wmic csproduct get UUID
		$a_03_2 = {46 69 6c 65 4c 6f 63 6b 65 72 2d 6d 61 73 74 65 72 5c 90 02 30 5c 44 65 73 6b 31 2e 70 64 62 90 00 } //01 00 
		$a_01_3 = {44 00 65 00 73 00 6b 00 31 00 2e 00 65 00 78 00 65 00 } //00 00  Desk1.exe
	condition:
		any of ($a_*)
 
}