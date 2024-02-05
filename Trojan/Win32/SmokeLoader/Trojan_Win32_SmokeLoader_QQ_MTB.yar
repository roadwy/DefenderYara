
rule Trojan_Win32_SmokeLoader_QQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 89 45 90 01 01 8d 45 90 01 01 50 c7 05 90 01 08 e8 90 01 04 8d 04 33 33 45 90 01 01 81 c3 90 01 04 31 45 90 01 01 2b 7d 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}