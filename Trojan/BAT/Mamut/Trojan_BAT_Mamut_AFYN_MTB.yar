
rule Trojan_BAT_Mamut_AFYN_MTB{
	meta:
		description = "Trojan:BAT/Mamut.AFYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 25 2e 42 07 17 59 16 31 0d 02 07 17 59 6f 90 01 03 0a 1f 25 2e 2f 07 17 58 02 6f 90 01 03 0a 2f 0d 02 07 17 58 6f 90 01 03 0a 1f 25 2e 17 11 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}