
rule Trojan_BAT_XWorm_PHU_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 04 07 8e 69 5d 91 13 05 06 11 04 8f ?? 00 00 01 25 47 11 05 1d 5a 20 00 01 00 00 5d d2 61 d2 52 08 11 04 06 11 04 91 11 04 1f 0d 5a 20 00 01 00 00 5d 59 11 05 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 b9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}