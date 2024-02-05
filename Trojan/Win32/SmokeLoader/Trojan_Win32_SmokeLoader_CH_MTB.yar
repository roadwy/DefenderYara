
rule Trojan_Win32_SmokeLoader_CH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b c3 d3 e8 03 45 d0 89 45 f8 8b 45 ec 31 45 fc 8b 45 fc 33 45 f8 29 45 e4 89 45 fc 8d 45 e8 e8 90 02 04 ff 4d e0 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}