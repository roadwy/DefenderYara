
rule Trojan_Win32_Ekstak_ASDS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b 54 24 04 56 56 8d 4c 24 10 56 51 56 52 c7 44 24 2c 02 00 00 00 c7 44 24 20 01 00 00 00 ff 15 90 01 02 4c 00 8b f0 8b 44 24 04 f7 de 1b f6 90 00 } //05 00 
		$a_03_1 = {8b 46 24 8b 4c 24 0c 8b 56 20 03 c1 8b 4c 24 08 57 03 ca 8b 56 04 50 51 52 89 4c 24 18 89 44 24 1c ff 15 90 01 02 4c 00 8b 4e 08 8d 44 24 10 50 51 89 7c 24 18 89 7c 24 1c ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}