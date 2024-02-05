
rule Ransom_Win32_NoEscape_YAA_MTB{
	meta:
		description = "Ransom:Win32/NoEscape.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 c1 8b 4d 84 c1 c0 0d 33 c8 8b 45 a4 03 c1 89 4d 84 c1 c0 12 33 d0 8b 4d a0 8b 45 b4 03 c6 c1 c0 07 33 c8 8b 45 b4 03 c1 89 4d a0 c1 c0 09 31 45 ac 8b 45 ac 03 c1 8b 4d 94 c1 c0 0d } //00 00 
	condition:
		any of ($a_*)
 
}