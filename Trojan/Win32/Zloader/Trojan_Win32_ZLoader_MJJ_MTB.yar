
rule Trojan_Win32_ZLoader_MJJ_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.MJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d6 8a 04 0e 88 04 1e 8b 55 dc 88 14 0e 8b 4d 08 0f b6 04 1e 01 d0 0f b6 c0 8a 04 06 30 04 39 47 ff 75 0c 57 e8 ?? ?? ?? ?? 83 c4 08 a8 01 0f 84 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}