
rule Trojan_BAT_Redline_GAT_MTB{
	meta:
		description = "Trojan:BAT/Redline.GAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 d2 13 06 12 06 72 ?? ?? ?? ?? 28 ?? ?? ?? 0a 13 05 06 11 04 11 05 a2 07 11 05 11 04 d2 6f ?? ?? ?? 0a 07 11 05 6f ?? ?? ?? 0a 11 04 d2 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2d bc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}