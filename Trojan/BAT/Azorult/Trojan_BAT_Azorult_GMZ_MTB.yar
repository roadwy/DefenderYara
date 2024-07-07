
rule Trojan_BAT_Azorult_GMZ_MTB{
	meta:
		description = "Trojan:BAT/Azorult.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0a 14 17 8d 01 00 00 01 25 16 28 90 01 03 06 a2 6f 90 01 03 0a 6f 90 01 03 0a 07 2b 06 0a 2b b4 0b 2b ba 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}