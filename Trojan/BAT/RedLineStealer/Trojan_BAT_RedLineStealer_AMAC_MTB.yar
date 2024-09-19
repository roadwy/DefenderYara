
rule Trojan_BAT_RedLineStealer_AMAC_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {08 5d 08 58 13 16 11 16 08 5d 13 17 07 11 17 91 } //2
		$a_01_1 = {09 8e 69 5d 09 8e 69 58 13 } //1
		$a_01_2 = {07 11 1a 91 13 1b 11 1b 11 12 61 13 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=5
 
}