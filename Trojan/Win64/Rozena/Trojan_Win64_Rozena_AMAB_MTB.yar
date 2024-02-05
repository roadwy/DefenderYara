
rule Trojan_Win64_Rozena_AMAB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 3b 45 18 7d 90 01 01 8b 45 fc 48 98 48 8b 55 28 48 83 ea 01 48 39 d0 75 90 01 01 c7 45 fc 90 01 04 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}