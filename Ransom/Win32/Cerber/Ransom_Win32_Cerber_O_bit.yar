
rule Ransom_Win32_Cerber_O_bit{
	meta:
		description = "Ransom:Win32/Cerber.O!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 50 68 b5 af b3 69 6a 08 68 90 01 03 00 e8 90 01 03 ff 83 c4 0c 50 ff 15 90 01 03 00 50 ff 15 90 01 03 00 90 00 } //01 00 
		$a_03_1 = {68 d7 a3 a4 2a 6a 0c 68 90 01 03 00 e8 90 01 03 00 83 c4 0c 50 68 90 01 03 00 ff 15 90 01 03 00 83 c4 0c 68 a5 de a6 b4 6a 18 68 90 01 03 00 e8 90 01 03 00 83 c4 0c 50 e8 90 01 03 ff 59 68 c0 18 5a fc 6a 05 68 90 01 03 00 e8 90 01 03 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}