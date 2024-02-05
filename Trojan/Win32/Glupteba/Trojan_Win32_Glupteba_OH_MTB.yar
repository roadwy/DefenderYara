
rule Trojan_Win32_Glupteba_OH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 39 83 90 02 02 90 18 47 3b 90 01 01 90 18 81 90 02 05 90 18 8b 90 02 05 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}