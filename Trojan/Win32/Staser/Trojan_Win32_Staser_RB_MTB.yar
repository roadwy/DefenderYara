
rule Trojan_Win32_Staser_RB_MTB{
	meta:
		description = "Trojan:Win32/Staser.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 e8 90 01 04 59 ff 75 14 ff 15 90 01 04 e8 90 01 04 31 05 90 01 04 68 90 01 04 e8 90 01 04 59 a3 90 01 04 e8 90 01 04 8b c8 b8 90 01 04 33 d2 f7 f1 31 05 90 01 04 e8 90 01 04 33 c0 50 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}