
rule Trojan_BAT_Barys_GPA_MTB{
	meta:
		description = "Trojan:BAT/Barys.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d [0-20] 17 58 09 5d 91 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}