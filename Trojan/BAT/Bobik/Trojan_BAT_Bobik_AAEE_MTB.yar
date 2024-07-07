
rule Trojan_BAT_Bobik_AAEE_MTB{
	meta:
		description = "Trojan:BAT/Bobik.AAEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 2d 20 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0a 06 80 90 01 01 00 00 04 7e 90 01 01 00 00 04 2a 90 00 } //3
		$a_01_1 = {44 00 61 00 74 00 61 00 45 00 76 00 6f 00 53 00 6f 00 66 00 74 00 2e 00 52 00 65 00 73 00 31 00 } //1 DataEvoSoft.Res1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}