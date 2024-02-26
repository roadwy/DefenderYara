
rule Trojan_BAT_Taskun_KAF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {13 05 06 17 58 13 0b 06 09 5d 13 06 11 0b 09 5d 13 0c 08 11 0c 91 11 05 58 13 0d 08 11 06 91 13 0e 11 0e 11 07 06 1f 16 5d 91 61 13 0f 11 0f 11 0d 59 13 10 08 11 06 11 10 11 05 5d d2 9c 06 17 58 0a 06 09 11 08 17 58 5a 32 b0 } //00 00 
	condition:
		any of ($a_*)
 
}