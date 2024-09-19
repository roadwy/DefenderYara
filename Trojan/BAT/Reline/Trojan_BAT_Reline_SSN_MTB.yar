
rule Trojan_BAT_Reline_SSN_MTB{
	meta:
		description = "Trojan:BAT/Reline.SSN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 2b 00 00 01 25 71 2b 00 00 01 20 82 00 00 00 58 d2 81 2b 00 00 01 02 11 20 8f 2b 00 00 01 25 71 2b 00 00 01 1f 44 59 d2 81 2b 00 00 01 00 11 20 17 58 13 20 11 20 02 8e 69 fe 04 13 21 11 21 2d b0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}