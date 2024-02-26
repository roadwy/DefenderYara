
rule Trojan_Win32_Glupteba_GNW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 08 81 c6 90 01 04 81 c0 04 00 00 00 89 da 01 d6 39 f8 90 01 02 29 f6 c3 31 30 b9 90 01 04 81 c0 04 00 00 00 39 d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}