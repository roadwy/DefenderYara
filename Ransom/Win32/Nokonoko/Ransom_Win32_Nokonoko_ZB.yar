
rule Ransom_Win32_Nokonoko_ZB{
	meta:
		description = "Ransom:Win32/Nokonoko.ZB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba d0 03 5c 09 b9 30 59 aa 00 e8 bf 1d 00 00 } //01 00 
		$a_01_1 = {ba e2 08 85 99 b9 30 59 aa 00 e8 8b 1d 00 00 } //01 00 
		$a_01_2 = {ba 12 56 e9 cc b9 30 59 aa 00 e8 6d 1d 00 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}