
rule Trojan_BAT_Kryptik_JR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.JR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0b 06 07 16 07 8e 69 6f 90 02 04 26 07 72 90 02 04 28 90 02 04 0b 07 28 90 02 04 6f 90 02 04 14 14 6f 90 02 04 26 de 0a 90 00 } //02 00 
		$a_80_1 = {23 50 41 53 53 57 4f 52 44 } //#PASSWORD  02 00 
		$a_80_2 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //get_EntryPoint  02 00 
		$a_80_3 = {49 6e 76 6f 6b 65 } //Invoke  00 00 
	condition:
		any of ($a_*)
 
}