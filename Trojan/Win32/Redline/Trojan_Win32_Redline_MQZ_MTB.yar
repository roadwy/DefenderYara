
rule Trojan_Win32_Redline_MQZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 85 c8 fd ff ff 8b 9d cc fd ff ff 8a 84 05 f8 fe ff ff 30 03 43 89 9d cc fd ff ff 81 fb 90 01 04 7d 11 8b 9d c4 fd ff ff 8b b5 c0 fd ff ff e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}