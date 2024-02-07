
rule Trojan_Win32_Taesb_C{
	meta:
		description = "Trojan:Win32/Taesb.C,SIGNATURE_TYPE_PEHSTR,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 54 00 6f 00 65 00 54 00 51 00 38 00 39 00 33 00 38 00 53 00 30 00 36 00 65 00 35 00 62 00 57 00 79 00 } //0a 00  *\AC:\ToeTQ8938S06e5bWy
		$a_01_1 = {6f 00 79 00 75 00 72 00 7a 00 63 00 } //01 00  oyurzc
		$a_01_2 = {5a 68 10 de 02 11 68 14 de 02 11 52 e9 } //00 00 
	condition:
		any of ($a_*)
 
}