
rule Trojan_Win32_Glupteba_OB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 1e 81 ff 90 01 04 90 18 46 3b f7 90 18 90 18 51 a1 90 02 04 69 90 02 05 a3 90 02 04 c7 90 02 06 81 90 02 1a 25 90 02 05 c3 90 00 } //01 00 
		$a_02_1 = {6a 00 6a 00 e8 90 02 04 46 3b 90 01 01 90 18 e8 90 02 04 30 04 90 01 01 81 ff 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}