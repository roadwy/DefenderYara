
rule Trojan_BAT_Injuke_ANW_MTB{
	meta:
		description = "Trojan:BAT/Injuke.ANW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {04 07 91 06 59 d2 9c 00 07 17 58 0b 07 7e 90 01 03 04 8e 69 fe 04 0c 08 2d db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}