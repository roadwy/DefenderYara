
rule Trojan_BAT_Taskun_AMBA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 08 11 04 5d 13 09 11 08 11 05 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 09 91 08 11 0a 91 61 13 0c 20 00 01 00 00 13 0d 11 0c 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0f 11 0f 2d a9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 1f 16 6a 5d d4 91 61 28 90 01 01 00 00 0a 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 90 01 01 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 0a 9c 11 07 17 6a 58 13 07 11 07 07 8e 69 17 59 09 17 58 5a 6a 31 a4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}