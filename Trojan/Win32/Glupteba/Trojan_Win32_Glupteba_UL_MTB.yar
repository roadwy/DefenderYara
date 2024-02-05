
rule Trojan_Win32_Glupteba_UL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {42 01 d7 01 ea 31 33 81 c3 90 01 04 b9 90 01 04 39 c3 75 ea c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}