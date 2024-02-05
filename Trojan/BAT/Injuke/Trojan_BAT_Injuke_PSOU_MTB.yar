
rule Trojan_BAT_Injuke_PSOU_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PSOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {14 0a 38 13 00 00 00 00 02 28 04 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c ea } //00 00 
	condition:
		any of ($a_*)
 
}