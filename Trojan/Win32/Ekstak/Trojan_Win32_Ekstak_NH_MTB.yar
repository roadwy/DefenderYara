
rule Trojan_Win32_Ekstak_NH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 45 fc 33 01 55 68 90 01 04 01 ff 30 64 89 90 01 01 3b 01 7e 90 00 } //0a 00 
		$a_03_1 = {0f b6 d3 88 01 17 b9 90 01 04 01 c6 33 d2 f7 f1 89 01 4b 85 f6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}