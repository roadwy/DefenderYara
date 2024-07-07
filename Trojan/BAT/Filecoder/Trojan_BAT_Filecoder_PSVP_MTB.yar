
rule Trojan_BAT_Filecoder_PSVP_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PSVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 06 6f 25 00 00 0a 06 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0b 28 90 01 01 00 00 0a 7e 03 00 00 04 28 90 01 01 00 00 0a 07 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}