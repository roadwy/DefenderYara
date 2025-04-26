
rule Trojan_Win32_LummaC_EAZZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 83 e9 01 89 4d f0 83 7d f0 00 76 3f 8b 55 f8 0f b7 02 03 45 fc 89 45 fc 8b 4d f8 0f b7 51 02 c1 e2 0b 33 55 fc 89 55 e8 8b 45 fc c1 e0 10 33 45 e8 89 45 fc 8b 4d f8 83 c1 04 89 4d f8 8b 55 fc c1 ea 0b 03 55 fc 89 55 fc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}