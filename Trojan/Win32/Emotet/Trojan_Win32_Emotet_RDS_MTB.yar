
rule Trojan_Win32_Emotet_RDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 b9 90 01 04 99 f7 f9 8b 45 90 01 01 8a 8c 15 90 01 04 30 08 40 ff 4d 90 01 01 89 45 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}