
rule Ransom_Win32_Rapidstop_YAA_MTB{
	meta:
		description = "Ransom:Win32/Rapidstop.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 0b 8b 83 a4 00 00 00 33 43 7c 33 43 54 33 43 2c 33 43 04 89 4d ac 8b 8b a8 00 00 00 33 8b 80 00 00 00 33 4b 58 33 4b 30 33 4b 08 89 45 b0 } //01 00 
		$a_03_1 = {f7 f9 33 74 d5 90 01 01 33 7c d5 b0 8b 55 fc 8b c2 31 30 8d 40 28 31 78 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}