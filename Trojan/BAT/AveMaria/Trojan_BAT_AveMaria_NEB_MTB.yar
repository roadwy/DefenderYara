
rule Trojan_BAT_AveMaria_NEB_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 02 11 04 02 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 11 04 91 28 ?? ?? ?? 06 9c 11 04 17 58 13 04 11 04 7e ?? ?? ?? 04 8e 69 fe 04 13 05 11 05 2d c5 } //1
		$a_01_1 = {51 00 31 00 30 00 56 00 42 00 49 00 49 00 38 00 4a 00 44 00 53 00 35 00 48 00 43 00 42 00 } //1 Q10VBII8JDS5HCB
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}