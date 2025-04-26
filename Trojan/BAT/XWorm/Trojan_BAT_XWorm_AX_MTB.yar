
rule Trojan_BAT_XWorm_AX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 13 05 11 05 07 6f ?? ?? ?? 0a 17 73 27 00 00 0a 13 06 00 02 28 ?? ?? ?? 0a 0c 11 06 08 16 08 8e 69 6f ?? ?? ?? 0a 00 11 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}