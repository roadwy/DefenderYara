
rule Trojan_BAT_StealerC_NE_MTB{
	meta:
		description = "Trojan:BAT/StealerC.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0c 11 07 58 11 09 59 93 61 11 0b ?? 2c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}