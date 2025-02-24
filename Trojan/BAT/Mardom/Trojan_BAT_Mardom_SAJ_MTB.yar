
rule Trojan_BAT_Mardom_SAJ_MTB{
	meta:
		description = "Trojan:BAT/Mardom.SAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 24 00 00 0a 25 73 25 00 00 0a 25 00 28 11 00 00 0a 72 ?? ?? ?? 70 28 12 00 00 0a 6f 13 00 00 0a 6f 26 00 00 0a 00 25 00 28 11 00 00 0a 72 ?? ?? ?? 70 28 12 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}