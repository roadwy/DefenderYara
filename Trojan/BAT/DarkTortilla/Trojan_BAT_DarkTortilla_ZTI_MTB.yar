
rule Trojan_BAT_DarkTortilla_ZTI_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.ZTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 07 09 91 08 61 9c 09 1f 09 d6 0d 00 09 07 8e 69 fe 04 13 05 11 05 2d e6 07 0a 2b 00 06 2a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}