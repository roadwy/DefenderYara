
rule Trojan_BAT_Zmutzy_GPD_MTB{
	meta:
		description = "Trojan:BAT/Zmutzy.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 17 58 11 [0-30] 59 20 00 01 00 00 58 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}