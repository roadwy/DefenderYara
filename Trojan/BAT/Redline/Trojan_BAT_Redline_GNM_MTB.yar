
rule Trojan_BAT_Redline_GNM_MTB{
	meta:
		description = "Trojan:BAT/Redline.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 06 07 6f ?? ?? ?? 0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 17 73 ?? ?? ?? 0a 13 06 11 06 08 16 08 8e 69 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 07 dd 33 00 00 00 11 06 39 07 00 00 00 11 06 6f ?? ?? ?? 0a dc 11 05 39 07 00 00 00 11 05 6f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}