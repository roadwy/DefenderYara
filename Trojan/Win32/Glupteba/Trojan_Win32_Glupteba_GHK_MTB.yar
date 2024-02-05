
rule Trojan_Win32_Glupteba_GHK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5f 81 c6 01 00 00 00 e8 90 01 04 29 f2 31 3b 81 ee 90 01 04 43 81 ea 90 01 04 39 cb 75 da 09 f2 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}