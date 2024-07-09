
rule Trojan_BAT_Seraph_SPAL_MTB{
	meta:
		description = "Trojan:BAT/Seraph.SPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 02 28 ?? ?? ?? 06 14 14 14 6f ?? ?? ?? 0a 26 00 16 2d ea } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}