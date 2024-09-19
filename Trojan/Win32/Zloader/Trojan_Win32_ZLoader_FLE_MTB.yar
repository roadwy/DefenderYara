
rule Trojan_Win32_ZLoader_FLE_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.FLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d9 0f b6 c1 8a 14 06 88 14 2e 88 1c 06 0f b6 04 2e 01 d8 0f b6 c0 8a 04 06 8b 74 24 08 30 07 47 4e 75 c4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}