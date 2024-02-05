
rule Trojan_Win32_Staser_DHA_MTB{
	meta:
		description = "Trojan:Win32/Staser.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {7d 60 8b 85 90 01 04 0f af 85 90 01 04 8b 0d 90 01 04 2b c8 89 0d 90 1b 02 a1 90 01 04 2b 05 90 1b 02 a3 90 01 04 8b 85 90 1b 01 99 b9 40 42 0f 00 f7 f9 85 d2 75 21 8b 85 90 01 04 83 c0 03 89 85 90 01 04 8b 85 90 01 04 03 85 90 1b 01 89 85 90 01 04 eb 87 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}