
rule Trojan_Win32_Glupteba_XS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 3b 89 c6 81 ee 90 01 04 81 c3 90 01 04 39 cb 90 01 02 09 c0 81 c2 90 01 04 c3 21 c2 40 81 c6 90 01 04 39 fe 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}