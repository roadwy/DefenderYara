
rule Backdoor_BAT_Webshell_SPXF_MTB{
	meta:
		description = "Backdoor:BAT/Webshell.SPXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 73 1b 00 00 0a 06 06 6f ?? ?? ?? 0a 07 16 07 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}