
rule Trojan_Win32_Glupteba_PPD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 04 24 00 00 00 00 8b 44 24 90 01 01 89 04 24 8b 90 01 01 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01 83 c4 3c 90 00 } //01 00 
		$a_01_1 = {8b 44 24 10 29 44 24 14 81 44 24 24 47 86 c8 61 83 ed 01 } //00 00 
	condition:
		any of ($a_*)
 
}