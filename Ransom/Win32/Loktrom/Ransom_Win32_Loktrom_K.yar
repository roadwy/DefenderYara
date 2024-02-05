
rule Ransom_Win32_Loktrom_K{
	meta:
		description = "Ransom:Win32/Loktrom.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 03 8b 13 8b 52 2c 89 42 25 c7 42 21 } //01 00 
		$a_03_1 = {6a 00 8b 46 18 8b 40 1c 50 e8 90 01 04 8b d8 85 db 74 90 01 01 8b 46 18 3b 58 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}