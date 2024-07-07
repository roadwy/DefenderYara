
rule Trojan_BAT_Heracles_PSIG_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 6b 00 00 70 13 07 20 00 00 00 00 7e 90 01 03 04 7b 90 01 03 04 39 90 01 03 ff 26 20 01 00 00 00 38 90 01 03 ff 11 05 11 01 8e 69 3f 90 01 03 ff 20 05 00 00 00 38 90 01 03 ff 11 04 13 09 20 02 00 00 00 38 90 01 03 ff 28 90 01 03 0a 11 07 6f 90 01 03 0a 13 03 38 6d 90 01 03 dd 76 00 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}