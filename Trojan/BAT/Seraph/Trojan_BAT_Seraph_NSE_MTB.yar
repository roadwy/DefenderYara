
rule Trojan_BAT_Seraph_NSE_MTB{
	meta:
		description = "Trojan:BAT/Seraph.NSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8f 10 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 } //01 00 
		$a_01_1 = {45 76 61 64 69 6e 67 53 70 6f 6f 66 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}