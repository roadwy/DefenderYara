
rule Trojan_BAT_Ribaj_A{
	meta:
		description = "Trojan:BAT/Ribaj.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 61 00 62 00 69 00 72 00 2e 00 62 00 } //01 00  jabir.b
		$a_01_1 = {68 00 2e 00 65 00 78 00 65 00 } //01 00  h.exe
		$a_01_2 = {31 00 31 00 31 00 31 00 31 00 31 00 } //01 00  111111
		$a_01_3 = {2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 77 00 69 00 6e 00 65 00 78 00 65 00 } //00 00  /target:winexe
	condition:
		any of ($a_*)
 
}