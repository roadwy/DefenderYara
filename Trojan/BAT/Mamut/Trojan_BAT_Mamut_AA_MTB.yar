
rule Trojan_BAT_Mamut_AA_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 28 28 00 00 06 07 8e 69 5e 13 04 08 09 07 11 04 e0 9a a2 09 17 58 0d 00 09 06 fe 04 13 16 11 16 2d db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}