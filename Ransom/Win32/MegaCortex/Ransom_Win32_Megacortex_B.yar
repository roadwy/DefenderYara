
rule Ransom_Win32_Megacortex_B{
	meta:
		description = "Ransom:Win32/Megacortex.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 42 00 41 00 44 00 41 00 4e 00 20 00 50 00 49 00 5a 00 5a 00 41 00 20 00 4c 00 54 00 44 00 } //00 00  ABADAN PIZZA LTD
	condition:
		any of ($a_*)
 
}