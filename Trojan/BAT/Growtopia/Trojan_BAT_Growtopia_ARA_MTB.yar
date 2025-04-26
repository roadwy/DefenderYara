
rule Trojan_BAT_Growtopia_ARA_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 91 72 ?? ?? ?? 70 08 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 06 11 06 2d d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}