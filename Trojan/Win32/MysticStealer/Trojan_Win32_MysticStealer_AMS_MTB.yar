
rule Trojan_Win32_MysticStealer_AMS_MTB{
	meta:
		description = "Trojan:Win32/MysticStealer.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 0c 97 95 e9 d1 5b 42 69 f6 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f1 3b d3 } //00 00 
	condition:
		any of ($a_*)
 
}