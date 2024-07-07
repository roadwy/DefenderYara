
rule Trojan_Win32_Dridex_OV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 5c 8b 4c 24 4c 83 e1 1f 83 c1 00 8a 54 24 1b 80 ea 8c 88 90 02 06 8a 14 08 88 54 24 43 8b 44 24 5c 89 04 24 e8 0e e9 ff ff b2 70 8b 4c 24 4c 8a 74 24 1b 28 f2 8b 75 0c 88 90 02 06 8b 7c 24 5c 8a 14 0e 8a 5c 24 43 0f b6 ca 0f b6 f3 29 f1 89 3c 24 89 44 24 08 89 4c 24 04 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}