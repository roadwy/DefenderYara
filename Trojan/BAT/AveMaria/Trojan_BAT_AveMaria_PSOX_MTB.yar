
rule Trojan_BAT_AveMaria_PSOX_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.PSOX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 20 00 0c 00 00 28 90 01 03 0a 00 7e 3d 00 00 04 72 9e 08 00 70 6f 90 01 03 0a 80 3e 00 00 04 16 0a 2b 1b 00 7e 3e 00 00 04 06 7e 3e 00 00 04 06 91 20 36 03 00 00 59 d2 9c 00 06 17 58 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}