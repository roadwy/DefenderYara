
rule Trojan_BAT_Tedy_NAB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 2a 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? 7a 00 06 58 54 2a } //5
		$a_81_1 = {32 64 38 61 32 36 62 37 2d 30 32 62 36 2d 34 38 66 30 2d 61 34 38 30 2d 61 64 64 38 36 39 39 36 33 35 39 39 } //1 2d8a26b7-02b6-48f0-a480-add869963599
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}