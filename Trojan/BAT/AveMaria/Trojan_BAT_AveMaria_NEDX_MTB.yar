
rule Trojan_BAT_AveMaria_NEDX_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c 11 04 03 6f ?? 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd } //10
		$a_01_1 = {70 00 72 00 30 00 74 00 30 00 74 00 79 00 70 00 33 00 } //5 pr0t0typ3
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}