
rule Trojan_BAT_Taskun_SM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 08 09 08 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 2f c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}