
rule Trojan_Win32_Redline_SA_MTB{
	meta:
		description = "Trojan:Win32/Redline.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e8 8d 4c 24 14 89 44 24 14 e8 90 01 04 8b 4c 24 14 33 4c 24 2c 89 35 90 01 04 31 4c 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 40 29 44 24 18 4b 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}