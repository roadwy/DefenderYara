
rule Trojan_BAT_Injector_SA_bit{
	meta:
		description = "Trojan:BAT/Injector.SA!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 69 61 6f 77 75 70 61 69 6b 65 } //02 00  jiaowupaike
		$a_03_1 = {08 09 1e 58 91 08 09 91 1a 58 33 90 01 01 08 09 1c 58 91 08 09 91 19 58 33 90 01 01 08 09 18 58 91 08 09 91 17 58 33 90 01 01 08 09 1a 58 91 08 09 91 18 58 33 90 01 01 16 13 04 90 00 } //02 00 
		$a_03_2 = {06 11 04 08 18 11 04 5a 09 58 1f 0a 58 91 08 09 1b 58 91 90 02 05 61 d2 9c 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 d4 
	condition:
		any of ($a_*)
 
}