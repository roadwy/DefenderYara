
rule Trojan_BAT_Rozena_SXXP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SXXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {07 08 06 08 93 28 90 01 03 0a 9c 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 3a ca fc ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}