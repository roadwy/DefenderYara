
rule Trojan_Win32_Dridex_DEH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c6 fb 81 c2 90 01 04 03 f1 03 da 0f b7 c6 8b 54 24 10 8b 35 90 01 04 c1 e6 06 2b 35 90 01 04 8b 12 89 54 24 0c 8b d0 03 f2 90 00 } //01 00 
		$a_02_1 = {8b c1 03 f0 a3 90 01 04 89 3d 90 01 04 8d 5c 33 ad 8a ca 8a c3 f6 e9 8a c8 a1 90 01 04 02 0d 90 01 04 05 90 01 04 a3 90 01 04 89 45 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}