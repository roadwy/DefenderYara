
rule Trojan_BAT_Tedy_PSFX_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 48 07 28 90 01 03 06 0c 08 17 2e 08 08 20 90 01 03 ff 33 31 02 7b 90 01 03 04 17 73 90 01 03 0a 0d 02 7b 90 01 03 04 18 28 90 01 03 0a 07 28 90 01 03 06 13 04 09 11 04 6f 90 01 03 0a 09 6f 90 01 03 0a 2b b8 07 17 58 0b 07 20 90 01 03 00 32 b0 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}