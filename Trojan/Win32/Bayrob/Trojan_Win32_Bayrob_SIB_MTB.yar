
rule Trojan_Win32_Bayrob_SIB_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c1 89 da 90 01 01 90 02 60 89 11 83 c1 04 90 02 30 83 ea 90 01 01 90 02 0a 75 90 00 } //01 00 
		$a_03_1 = {31 db e9 e3 90 02 30 8b 8a 90 01 04 90 02 10 33 1c 8f 90 02 a0 83 c2 04 90 02 0a 39 d0 90 02 0a 0f 84 90 01 04 90 02 50 e9 90 00 } //01 00 
		$a_03_2 = {89 74 24 04 89 3c 24 90 02 30 e8 90 01 04 90 02 30 89 3c 24 90 02 0a e8 90 01 04 90 02 40 33 1d 69 76 43 00 90 02 aa b8 20 51 43 00 29 d8 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}