
rule Trojan_BAT_PureCrypter_APU_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.APU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {14 fe 03 13 09 20 00 00 d5 09 00 fe 0e 0e 00 00 fe 0d 0e 00 48 68 d3 13 0d 2b cb 11 09 2c 71 20 03 00 0b 7a fe 0e 0e 00 00 fe 0d 0e 00 00 48 68 d3 13 0d 2b b1 2b 00 00 11 08 } //00 00 
	condition:
		any of ($a_*)
 
}