
rule Trojan_BAT_Mardom_GTR_MTB{
	meta:
		description = "Trojan:BAT/Mardom.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 00 07 20 ?? ?? ?? ?? fe 01 39 ?? ?? ?? ?? fe 0d 00 00 7c ?? ?? ?? ?? fe 0d 00 00 28 ?? ?? ?? ?? 20 ?? ?? ?? 00 0b 00 07 20 ?? ?? ?? 00 fe 01 39 } //10
		$a_03_1 = {0b 00 07 20 ?? ?? ?? ?? fe 01 39 ?? ?? ?? 00 fe 0d 00 00 20 ?? ?? ?? ff 7d ?? ?? ?? 04 20 ?? ?? ?? 00 0b 00 07 20 ?? ?? ?? 00 fe 01 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}