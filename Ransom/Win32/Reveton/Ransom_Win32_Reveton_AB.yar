
rule Ransom_Win32_Reveton_AB{
	meta:
		description = "Ransom:Win32/Reveton.AB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 0f b6 54 1a ff 66 81 f2 9a 02 88 54 18 ff 43 4e 75 e3 } //01 00 
		$a_01_1 = {cc d3 c8 ce cf db d6 00 ff } //0a 00 
		$a_03_2 = {a7 02 00 00 6a 00 6a 04 8d 45 90 01 01 50 53 e8 90 01 04 40 0f 84 90 09 03 00 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}