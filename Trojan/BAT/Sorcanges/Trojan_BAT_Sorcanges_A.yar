
rule Trojan_BAT_Sorcanges_A{
	meta:
		description = "Trojan:BAT/Sorcanges.A,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6f 72 61 6e 67 65 2e 65 78 65 } //0a 00  orange.exe
		$a_01_1 = {6f 00 72 00 61 00 6e 00 67 00 65 00 74 00 65 00 67 00 68 00 61 00 6c 00 } //0a 00  orangeteghal
		$a_01_2 = {4d 00 69 00 76 00 65 00 20 00 4e 00 61 00 72 00 65 00 6e 00 67 00 69 00 } //0a 00  Mive Narengi
		$a_01_3 = {4d 00 50 00 52 00 45 00 53 00 53 00 } //00 00  MPRESS
	condition:
		any of ($a_*)
 
}