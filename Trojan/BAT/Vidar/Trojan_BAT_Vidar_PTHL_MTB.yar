
rule Trojan_BAT_Vidar_PTHL_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 fe 00 00 0a 28 90 01 01 00 00 0a 04 28 90 01 01 03 00 06 28 90 01 01 03 00 06 13 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}