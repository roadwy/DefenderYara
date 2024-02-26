
rule Trojan_Win32_Redline_CCCH_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 34 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 04 3e 90 01 01 ff d3 80 04 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}