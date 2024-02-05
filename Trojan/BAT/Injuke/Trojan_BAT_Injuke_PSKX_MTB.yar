
rule Trojan_BAT_Injuke_PSKX_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 2b 00 00 70 28 09 00 00 06 13 00 38 00 00 00 00 28 90 01 03 0a 11 00 6f 90 01 03 0a 72 75 00 00 70 7e 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 13 01 38 00 00 00 00 dd 10 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}