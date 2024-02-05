
rule Ransom_Win32_Makop_AY_MSR{
	meta:
		description = "Ransom:Win32/Makop.AY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 6f 67 20 63 65 6a 75 6d 75 20 73 69 76 61 6a 75 64 61 6b 61 6d 6f 66 20 64 69 77 69 78 6f } //Tog cejumu sivajudakamof diwixo  01 00 
		$a_80_1 = {65 64 7a 6a 6b 70 68 76 65 73 77 2e 75 78 65 } //edzjkphvesw.uxe  01 00 
		$a_80_2 = {26 3b 42 60 75 5d 61 } //&;B`u]a  01 00 
		$a_80_3 = {56 75 62 61 64 75 79 65 73 61 6c 6f 20 7a 65 6a 61 } //Vubaduyesalo zeja  01 00 
		$a_80_4 = {58 6f 7a 69 66 61 20 73 6f 68 75 70 69 63 6f 77 61 64 69 63 6f } //Xozifa sohupicowadico  00 00 
	condition:
		any of ($a_*)
 
}