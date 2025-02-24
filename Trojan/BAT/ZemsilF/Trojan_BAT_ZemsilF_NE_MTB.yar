
rule Trojan_BAT_ZemsilF_NE_MTB{
	meta:
		description = "Trojan:BAT/ZemsilF.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 fe 06 0f 00 00 06 73 ?? 00 00 0a 73 ?? 00 00 0a 0a 06 17 6f 3e 00 00 0a 00 06 6f 26 00 00 0a 00 2a } //2
		$a_01_1 = {28 0f 00 00 0a 13 06 11 06 6f 10 00 00 0a 13 07 11 07 72 0f 00 00 70 28 11 00 00 0a 72 19 00 00 70 28 12 00 00 0a } //2
		$a_01_2 = {64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2f 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 20 00 2b 00 } //1 desktop/ENCRYPTED +
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}