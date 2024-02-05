
rule Trojan_Win32_Dridex_ADJ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8a 11 88 10 8b 45 f4 83 c0 01 89 45 f4 8b 4d f0 83 c1 01 89 4d f0 8b 55 dc 83 ea 31 8b 45 e0 83 d8 00 33 c9 03 55 fc 13 c1 } //0a 00 
		$a_02_1 = {83 ea 09 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 83 e8 09 2b 05 90 01 04 66 a3 90 01 04 8b 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}