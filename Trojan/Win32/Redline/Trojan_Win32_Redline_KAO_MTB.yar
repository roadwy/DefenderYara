
rule Trojan_Win32_Redline_KAO_MTB{
	meta:
		description = "Trojan:Win32/Redline.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 c7 05 90 01 08 c7 05 90 01 08 89 44 24 14 8b 44 24 28 01 44 24 14 8b 4c 24 14 8b 44 24 10 33 cb 33 c1 2b f8 8d 44 24 18 e8 90 01 04 ff 4c 24 1c 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}