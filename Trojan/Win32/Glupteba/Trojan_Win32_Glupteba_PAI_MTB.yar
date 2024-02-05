
rule Trojan_Win32_Glupteba_PAI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 33 44 24 24 89 44 24 10 2b f0 8d 44 24 28 e8 90 01 04 83 6c 24 30 01 0f 85 90 00 } //01 00 
		$a_03_1 = {8b 4c 24 10 31 4c 24 24 8b 44 24 24 83 44 24 14 90 01 01 29 44 24 14 83 6c 24 14 90 01 01 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}