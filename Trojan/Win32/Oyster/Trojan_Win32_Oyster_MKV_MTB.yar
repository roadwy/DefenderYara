
rule Trojan_Win32_Oyster_MKV_MTB{
	meta:
		description = "Trojan:Win32/Oyster.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca c1 e9 04 6b c1 13 8b 4d fc 2b c8 03 cf 83 c7 06 0f b6 44 0d ?? 8b 4d ec 32 04 31 8b 4d fc 88 46 05 83 c6 06 81 ff 00 62 07 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}