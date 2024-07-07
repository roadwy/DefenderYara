
rule Trojan_BAT_SolarMarker_ZZ{
	meta:
		description = "Trojan:BAT/SolarMarker.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 1f 68 9d 11 90 01 01 17 1f 77 9d 11 90 01 01 18 1f 69 9d 11 90 01 01 19 1f 64 9d 90 00 } //5
		$a_03_1 = {16 1f 64 9d 11 90 01 01 17 1f 6e 9d 11 90 01 01 18 1f 73 9d 11 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}