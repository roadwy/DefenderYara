
rule Ransom_Win32_Snake_A{
	meta:
		description = "Ransom:Win32/Snake.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 07 96 88 90 01 03 96 45 39 90 01 01 7d 18 0f b6 34 2b 90 02 05 39 90 01 01 73 90 02 05 0f b6 3c 29 31 fe 90 02 06 72 df eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}