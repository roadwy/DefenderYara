
rule Ransom_Win32_Lyposit_C{
	meta:
		description = "Ransom:Win32/Lyposit.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff 51 38 3b c3 7c 90 01 01 83 7d 90 01 01 06 75 90 01 01 8b 45 e4 8b 08 50 ff 51 24 8b 45 0c 89 30 90 00 } //01 00 
		$a_01_1 = {8b 70 78 03 f2 8b 7e 20 03 fa 8b 5e 24 03 da 8b 46 1c 03 c2 } //01 00 
		$a_01_2 = {8b 45 08 8b 40 10 83 c4 14 be 01 00 00 80 83 f8 ff 74 07 3d 00 30 00 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}