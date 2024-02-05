
rule Trojan_BAT_PsDownload_HAB_MTB{
	meta:
		description = "Trojan:BAT/PsDownload.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {01 00 70 28 90 01 01 00 00 06 0a dd 90 01 01 00 00 00 26 dd 00 00 00 00 06 2c e6 16 0b 06 8e 69 17 59 0c 38 90 01 01 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}