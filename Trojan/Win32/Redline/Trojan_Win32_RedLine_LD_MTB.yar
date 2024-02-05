
rule Trojan_Win32_RedLine_LD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.LD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8b 40 04 ff 70 09 6a 00 8b 45 08 ff 50 24 89 45 f8 83 65 f4 90 01 01 6a 00 8d 45 f4 50 ff 75 f8 8b 45 08 8b 40 04 ff 30 ff 75 fc e8 90 01 04 83 c4 14 8b 45 f8 89 45 fc 8b 45 08 8b 40 04 8b 4d f4 89 08 ff 65 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}