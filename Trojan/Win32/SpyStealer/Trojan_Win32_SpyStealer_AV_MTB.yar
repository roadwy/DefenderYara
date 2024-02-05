
rule Trojan_Win32_SpyStealer_AV_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 04 0a 8b 4d f8 8b 49 04 8b 45 fc 33 d2 be 04 00 00 00 f7 f6 a1 90 02 04 0f be 14 10 8b 45 fc 0f b6 0c 01 33 ca 8b 55 f8 8b 42 04 8b 55 fc 88 0c 10 eb a9 90 00 } //01 00 
		$a_01_1 = {51 6a 40 68 7e 07 00 00 8b 55 e4 52 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}