
rule Trojan_Win32_Midie_KHT_MTB{
	meta:
		description = "Trojan:Win32/Midie.KHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 89 0d ?? ?? ?? ?? 8b 4d 0c 8a 44 38 08 32 04 0a 88 01 eb ?? 8b 4d 0c 8b 75 a4 8b 7d 84 41 83 ad 78 ff ff ff 01 89 4d 0c 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}