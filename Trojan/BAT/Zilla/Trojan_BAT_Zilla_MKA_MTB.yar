
rule Trojan_BAT_Zilla_MKA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 b7 01 00 70 13 06 72 f9 01 00 70 13 07 72 6d 01 00 70 28 2b 00 00 0a 6f 2c 00 00 0a 28 2d 00 00 0a 11 06 28 05 00 00 06 11 07 28 05 00 00 06 28 04 00 00 06 13 08 72 3b 02 00 70 11 08 8e 69 8c 30 00 00 01 } //25
		$a_81_1 = {70 61 79 6c 6f 61 64 2e 74 78 74 } //10 payload.txt
	condition:
		((#a_01_0  & 1)*25+(#a_81_1  & 1)*10) >=35
 
}