
rule Trojan_BAT_Stealer_DWAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.DWAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 61 } //00 00 
	condition:
		any of ($a_*)
 
}