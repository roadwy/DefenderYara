
rule Trojan_Win32_Emotet_DBO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 0f b6 44 34 90 01 01 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 90 03 01 03 45 83 c5 01 8a 54 14 90 01 01 30 55 ff 83 bc 24 90 01 04 00 0f 85 90 00 } //01 00 
		$a_02_1 = {6a 00 ff 15 90 01 04 0f b6 44 34 90 01 01 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 8a 18 8a 54 14 90 01 01 32 da 88 18 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}