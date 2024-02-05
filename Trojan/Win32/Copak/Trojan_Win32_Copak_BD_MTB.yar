
rule Trojan_Win32_Copak_BD_MTB{
	meta:
		description = "Trojan:Win32/Copak.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {31 10 4e 83 ec 04 c7 04 24 46 10 5d de 5e 81 c0 04 00 00 00 39 f8 75 e3 } //05 00 
		$a_01_1 = {81 ee 3c 08 a5 ee 01 f3 31 07 47 81 c3 d7 73 25 90 39 cf 75 e0 } //05 00 
		$a_01_2 = {31 1a 81 ee 01 00 00 00 21 cf 81 c2 04 00 00 00 39 c2 75 e7 } //00 00 
	condition:
		any of ($a_*)
 
}