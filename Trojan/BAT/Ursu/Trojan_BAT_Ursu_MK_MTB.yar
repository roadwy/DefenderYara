
rule Trojan_BAT_Ursu_MK_MTB{
	meta:
		description = "Trojan:BAT/Ursu.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 a2 25 17 72 13 00 00 70 a2 25 18 72 29 00 00 70 a2 25 19 72 3f 00 00 70 a2 25 1a 72 51 00 00 70 a2 25 1b 72 69 00 00 70 } //25
		$a_01_1 = {28 0f 00 00 0a 0a 06 72 05 01 00 70 6f 10 00 00 0a 0b 07 72 53 01 00 70 1f 28 } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}