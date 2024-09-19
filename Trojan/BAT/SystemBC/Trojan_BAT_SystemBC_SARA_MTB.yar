
rule Trojan_BAT_SystemBC_SARA_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.SARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 73 0d 00 00 0a 0d 09 08 17 73 0e 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 0a de 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}